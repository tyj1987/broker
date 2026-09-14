package auditchain

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func isChainFileName(name string) bool {
	return strings.HasPrefix(name, "audit-chain-") && strings.HasSuffix(name, ".jsonl")
}

type fileSnapshot struct {
	name string
	info os.FileInfo
}

type directorySnapshot struct {
	info  os.FileInfo
	files []fileSnapshot
	total int64
}

func scanDirectory(
	ctx context.Context,
	directory string,
	limits Limits,
	anchor *int64,
) (Proof, error) {
	if ctx == nil || !filepath.IsAbs(directory) || !validLimits(limits) {
		return Proof{}, ErrChainInvalid
	}
	if err := ctx.Err(); err != nil {
		return Proof{}, err
	}
	before, err := snapshotDirectory(directory, limits)
	if err != nil {
		return Proof{}, err
	}
	proof := Proof{
		State: State{Files: int64(len(before.files)), LastHash: GenesisHash},
	}
	if anchor != nil {
		proof.AnchoredEventCount = *anchor
		if *anchor == 0 {
			hash := GenesisHash
			files := int64(0)
			proof.HashAtAnchor = &hash
			proof.FilesAtAnchor = &files
		}
	}
	expectedPrevious := GenesisHash
	for index, file := range before.files {
		if err := ctx.Err(); err != nil {
			return Proof{}, err
		}
		err := scanStableFile(ctx, directory, file, limits, func(raw []byte) error {
			storedHash, previousHash, eventErr := canonicalEvent(raw, limits.MaxDepth)
			if eventErr != nil || previousHash != expectedPrevious {
				return ErrChainInvalid
			}
			if proof.Count >= limits.MaxEvents {
				return ErrChainLimit
			}
			proof.Count++
			proof.LastHash = storedHash
			expectedPrevious = storedHash
			if anchor != nil && proof.HashAtAnchor == nil && proof.Count == *anchor {
				hash := storedHash
				files := int64(index + 1)
				proof.HashAtAnchor = &hash
				proof.FilesAtAnchor = &files
			}
			return nil
		})
		if err != nil {
			return Proof{}, err
		}
	}
	after, err := snapshotDirectory(directory, limits)
	if err != nil {
		return Proof{}, err
	}
	if !sameDirectorySnapshot(before, after) {
		return Proof{}, ErrChainChanged
	}
	return proof, nil
}

func snapshotDirectory(directory string, limits Limits) (directorySnapshot, error) {
	metadata, err := os.Lstat(directory)
	if err != nil {
		return directorySnapshot{}, ErrChainRead
	}
	if !metadata.IsDir() || metadata.Mode()&os.ModeSymlink != 0 {
		return directorySnapshot{}, ErrChainInvalid
	}
	handle, err := os.Open(directory)
	if err != nil {
		return directorySnapshot{}, ErrChainRead
	}
	defer handle.Close()
	opened, err := handle.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(metadata, opened) {
		return directorySnapshot{}, ErrChainChanged
	}
	entries, err := handle.Readdir(-1)
	if err != nil {
		return directorySnapshot{}, ErrChainRead
	}
	selected := make([]fileSnapshot, 0, len(entries))
	var total int64
	for _, entry := range entries {
		if !isChainFileName(entry.Name()) {
			continue
		}
		if !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 || entry.Size() < 0 {
			return directorySnapshot{}, ErrChainInvalid
		}
		if len(selected) >= limits.MaxFiles || entry.Size() > limits.MaxTotalBytes-total {
			return directorySnapshot{}, ErrChainLimit
		}
		total += entry.Size()
		selected = append(selected, fileSnapshot{name: entry.Name(), info: entry})
	}
	sort.Slice(selected, func(left, right int) bool { return selected[left].name < selected[right].name })
	return directorySnapshot{info: opened, files: selected, total: total}, nil
}

func scanStableFile(
	ctx context.Context,
	directory string,
	snapshot fileSnapshot,
	limits Limits,
	onEvent func([]byte) error,
) error {
	path := filepath.Join(directory, snapshot.name)
	before, err := os.Lstat(path)
	if err != nil {
		return ErrChainChanged
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(snapshot.info, before) || !sameFileMetadata(snapshot.info, before) {
		return ErrChainChanged
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrChainRead
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !sameFileMetadata(before, opened) {
		return ErrChainChanged
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(splitLF)
	scanner.Buffer(make([]byte, min(limits.MaxLineBytes, 64*1024)), limits.MaxLineBytes+1)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if len(line) > limits.MaxLineBytes || onEvent == nil {
			return ErrChainLimit
		}
		if err := onEvent(line); err != nil {
			return err
		}
	}
	if scanner.Err() != nil {
		return ErrChainLimit
	}
	afterOpen, err := file.Stat()
	if err != nil {
		return ErrChainChanged
	}
	afterPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, afterOpen) || !os.SameFile(opened, afterPath) ||
		!sameFileMetadata(opened, afterOpen) || !sameFileMetadata(opened, afterPath) {
		return ErrChainChanged
	}
	return nil
}

func splitLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for index, value := range data {
		if value == '\n' {
			return index + 1, data[:index], nil
		}
	}
	if atEOF {
		if len(data) == 0 {
			return 0, nil, nil
		}
		return len(data), data, nil
	}
	return 0, nil, nil
}

func sameDirectorySnapshot(left, right directorySnapshot) bool {
	if !os.SameFile(left.info, right.info) || len(left.files) != len(right.files) || left.total != right.total {
		return false
	}
	for index := range left.files {
		if left.files[index].name != right.files[index].name ||
			!os.SameFile(left.files[index].info, right.files[index].info) ||
			!sameFileMetadata(left.files[index].info, right.files[index].info) {
			return false
		}
	}
	return true
}

func sameFileMetadata(left, right os.FileInfo) bool {
	return left.Mode() == right.Mode() && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}
