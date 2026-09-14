package auditchain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeChainFile(t *testing.T, directory, name string, events ...[]byte) {
	t.Helper()
	content := bytes.Join(events, []byte{'\n'})
	if len(events) > 0 {
		content = append(content, '\n')
	}
	if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func validThreeEventDirectory(t *testing.T) (string, [3][digestBytes]byte) {
	t.Helper()
	directory := t.TempDir()
	first := sealTestEvent(t, map[string]any{"sequence": 1}, GenesisHash)
	firstHash := digestFromEvent(t, first)
	second := sealTestEvent(t, map[string]any{"sequence": 2}, firstHash)
	secondHash := digestFromEvent(t, second)
	third := sealTestEvent(t, map[string]any{"sequence": 3}, secondHash)
	thirdHash := digestFromEvent(t, third)
	writeChainFile(t, directory, "audit-chain-2026-09-12.jsonl", first, second)
	writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl", third)
	if err := os.WriteFile(filepath.Join(directory, "audit-legacy.jsonl"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory, [3][digestBytes]byte{firstHash, secondHash, thirdHash}
}

func TestVerifyDirectoryAndHistoricalProof(t *testing.T) {
	directory, hashes := validThreeEventDirectory(t)
	state, err := VerifyDirectory(context.Background(), directory, DefaultLimits())
	if err != nil || state.Files != 2 || state.Count != 3 || state.LastHash != hashes[2] {
		t.Fatalf("VerifyDirectory() = (%+v, %v)", state, err)
	}
	proof, err := LoadProof(context.Background(), directory, 2, DefaultLimits())
	if err != nil || proof.HashAtAnchor == nil || *proof.HashAtAnchor != hashes[1] ||
		proof.FilesAtAnchor == nil || *proof.FilesAtAnchor != 1 || proof.Count != 3 {
		t.Fatalf("LoadProof(2) = (%+v, %v)", proof, err)
	}
	future, err := LoadProof(context.Background(), directory, 4, DefaultLimits())
	if err != nil || future.HashAtAnchor != nil || future.FilesAtAnchor != nil {
		t.Fatalf("LoadProof(4) = (%+v, %v)", future, err)
	}
	genesis, err := LoadProof(context.Background(), directory, 0, DefaultLimits())
	if err != nil || genesis.HashAtAnchor == nil || *genesis.HashAtAnchor != GenesisHash ||
		genesis.FilesAtAnchor == nil || *genesis.FilesAtAnchor != 0 {
		t.Fatalf("LoadProof(0) = (%+v, %v)", genesis, err)
	}
}

func TestVerifyDirectoryAllowsEmptyAndBlankLF(t *testing.T) {
	directory := t.TempDir()
	writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl")
	if err := os.WriteFile(filepath.Join(directory, "audit-chain-2026-09-14.jsonl"), []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := VerifyDirectory(context.Background(), directory, DefaultLimits())
	if err != nil || state.Files != 2 || state.Count != 0 || state.LastHash != GenesisHash {
		t.Fatalf("VerifyDirectory() = (%+v, %v)", state, err)
	}
}

func TestVerifyDirectoryIncludesNodeCompatibleNonDateFile(t *testing.T) {
	directory := t.TempDir()
	first := sealTestEvent(t, map[string]any{"sequence": 1}, GenesisHash)
	firstHash := digestFromEvent(t, first)
	second := sealTestEvent(t, map[string]any{"sequence": 2}, firstHash)
	writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl", first)
	writeChainFile(t, directory, "audit-chain-extra.jsonl", second)
	state, err := VerifyDirectory(context.Background(), directory, DefaultLimits())
	if err != nil || state.Files != 2 || state.Count != 2 || state.LastHash != digestFromEvent(t, second) {
		t.Fatalf("VerifyDirectory() = (%+v, %v)", state, err)
	}
}

func TestVerifyDirectoryRejectsBrokenChains(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"tampered event": func(t *testing.T, directory string) {
			raw := sealTestEvent(t, map[string]any{"value": "before"}, GenesisHash)
			raw = bytes.Replace(raw, []byte("before"), []byte("after!"), 1)
			writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl", raw)
		},
		"wrong previous": func(t *testing.T, directory string) {
			raw := sealTestEvent(t, map[string]any{"value": true}, [digestBytes]byte{1})
			writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl", raw)
		},
		"missing middle": func(t *testing.T, directory string) {
			first := sealTestEvent(t, map[string]any{"sequence": 1}, GenesisHash)
			firstHash := digestFromEvent(t, first)
			second := sealTestEvent(t, map[string]any{"sequence": 2}, firstHash)
			secondHash := digestFromEvent(t, second)
			third := sealTestEvent(t, map[string]any{"sequence": 3}, secondHash)
			writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl", first, third)
		},
		"carriage return only": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "audit-chain-2026-09-13.jsonl"), []byte("\r"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			arrange(t, directory)
			if _, err := VerifyDirectory(context.Background(), directory, DefaultLimits()); !errors.Is(err, ErrChainInvalid) {
				t.Fatalf("error = %v, want ErrChainInvalid", err)
			}
		})
	}
}

func TestVerifyDirectoryRejectsInvalidDirectory(t *testing.T) {
	limits := DefaultLimits()
	if _, err := VerifyDirectory(context.Background(), "relative", limits); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("relative error = %v", err)
	}
	if _, err := VerifyDirectory(context.Background(), filepath.Join(t.TempDir(), "missing"), limits); !errors.Is(err, ErrChainRead) {
		t.Fatalf("missing error = %v", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(context.Background(), file, limits); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("file error = %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err == nil {
		if _, err := VerifyDirectory(context.Background(), link, limits); !errors.Is(err, ErrChainInvalid) {
			t.Fatalf("symlink error = %v", err)
		}
	}
	matchingDirectory := filepath.Join(t.TempDir(), "audit-chain-2026-09-13.jsonl")
	if err := os.Mkdir(matchingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(context.Background(), filepath.Dir(matchingDirectory), limits); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("nonregular entry error = %v", err)
	}
}

func TestVerifyDirectoryEnforcesLimits(t *testing.T) {
	directory, _ := validThreeEventDirectory(t)
	tests := map[string]func(Limits) Limits{
		"files":  func(l Limits) Limits { l.MaxFiles = 1; return l },
		"events": func(l Limits) Limits { l.MaxEvents = 2; return l },
		"line":   func(l Limits) Limits { l.MaxLineBytes = 8; return l },
		"total":  func(l Limits) Limits { l.MaxTotalBytes = 8; return l },
	}
	for name, update := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyDirectory(context.Background(), directory, update(DefaultLimits())); !errors.Is(err, ErrChainLimit) && !errors.Is(err, ErrChainInvalid) {
				t.Fatalf("error = %v, want bounded failure", err)
			}
		})
	}
	invalid := DefaultLimits()
	invalid.MaxFiles = 0
	if _, err := VerifyDirectory(context.Background(), directory, invalid); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("invalid limits error = %v", err)
	}
	deepDirectory := t.TempDir()
	deep := sealTestEvent(t, map[string]any{"nested": map[string]any{"value": true}}, GenesisHash)
	writeChainFile(t, deepDirectory, "audit-chain-2026-09-13.jsonl", deep)
	depthLimit := DefaultLimits()
	depthLimit.MaxDepth = 1
	if _, err := VerifyDirectory(context.Background(), deepDirectory, depthLimit); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("depth error = %v, want ErrChainInvalid", err)
	}
}

func TestVerifyDirectoryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyDirectory(ctx, t.TempDir(), DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if _, err := VerifyDirectory(nil, t.TempDir(), DefaultLimits()); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestLoadProofRejectsInvalidAnchor(t *testing.T) {
	directory := t.TempDir()
	for _, value := range []int64{-1, MaxSafeInteger + 1} {
		if _, err := LoadProof(context.Background(), directory, value, DefaultLimits()); !errors.Is(err, ErrChainInvalid) {
			t.Fatalf("LoadProof(%d) error = %v", value, err)
		}
	}
}

func TestSnapshotComparisonDetectsMetadataChange(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit-chain-2026-09-13.jsonl")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := snapshotDirectory(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(time.Second)
	if err := os.Chtimes(path, now, now); err != nil {
		t.Fatal(err)
	}
	after, err := snapshotDirectory(directory, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if sameDirectorySnapshot(before, after) {
		t.Fatal("changed snapshot was accepted")
	}
	if !sameDirectorySnapshot(after, after) {
		t.Fatal("identical snapshot was rejected")
	}
	changedTotal := after
	changedTotal.total++
	if sameDirectorySnapshot(after, changedTotal) {
		t.Fatal("changed total was accepted")
	}
	changedName := after
	changedName.files = append([]fileSnapshot(nil), after.files...)
	changedName.files[0].name = "audit-chain-2026-09-14.jsonl"
	if sameDirectorySnapshot(after, changedName) {
		t.Fatal("changed name was accepted")
	}
}

func TestScanStableFileRejectsStaleSnapshotAndNilCallback(t *testing.T) {
	directory := t.TempDir()
	raw := sealTestEvent(t, map[string]any{"value": true}, GenesisHash)
	writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl", raw)
	snapshot, err := snapshotDirectory(directory, DefaultLimits())
	if err != nil || len(snapshot.files) != 1 {
		t.Fatalf("snapshotDirectory() = (%+v, %v)", snapshot, err)
	}
	if err := scanStableFile(context.Background(), directory, snapshot.files[0], DefaultLimits(), nil); !errors.Is(err, ErrChainLimit) {
		t.Fatalf("nil callback error = %v", err)
	}
	want := errors.New("callback stopped")
	if err := scanStableFile(context.Background(), directory, snapshot.files[0], DefaultLimits(), func([]byte) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback error = %v", err)
	}
	if err := os.Remove(filepath.Join(directory, snapshot.files[0].name)); err != nil {
		t.Fatal(err)
	}
	if err := scanStableFile(context.Background(), directory, snapshot.files[0], DefaultLimits(), func([]byte) error { return nil }); !errors.Is(err, ErrChainChanged) {
		t.Fatalf("removed file error = %v", err)
	}
}

func TestScanStableFileRejectsWrongFileIdentity(t *testing.T) {
	directory := t.TempDir()
	raw := sealTestEvent(t, map[string]any{"value": true}, GenesisHash)
	writeChainFile(t, directory, "audit-chain-2026-09-13.jsonl", raw)
	otherPath := filepath.Join(directory, "other")
	if err := os.WriteFile(otherPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := fileSnapshot{name: "audit-chain-2026-09-13.jsonl", info: other}
	if err := scanStableFile(context.Background(), directory, snapshot, DefaultLimits(), func([]byte) error { return nil }); !errors.Is(err, ErrChainChanged) {
		t.Fatalf("wrong identity error = %v", err)
	}
}

func TestSplitLFPreservesCarriageReturn(t *testing.T) {
	advance, token, err := splitLF([]byte("one\r\ntwo"), false)
	if err != nil || advance != 5 || string(token) != "one\r" {
		t.Fatalf("splitLF() = (%d, %q, %v)", advance, token, err)
	}
	advance, token, err = splitLF([]byte("tail"), true)
	if err != nil || advance != 4 || string(token) != "tail" {
		t.Fatalf("splitLF(atEOF) = (%d, %q, %v)", advance, token, err)
	}
	advance, token, err = splitLF(nil, true)
	if err != nil || advance != 0 || token != nil {
		t.Fatalf("splitLF(empty) = (%d, %q, %v)", advance, token, err)
	}
}

func TestChainFileNameMatchesNodeSelection(t *testing.T) {
	for _, name := range []string{"audit-chain-2026-09-13.jsonl.bak", "audit-2026-09-13.jsonl"} {
		if isChainFileName(name) {
			t.Fatalf("unexpected match: %s", name)
		}
	}
	for _, name := range []string{"audit-chain-2026-09-13.jsonl", "audit-chain-extra.jsonl", "audit-chain-.jsonl", "audit-chain-line\nbreak.jsonl"} {
		if !isChainFileName(name) {
			t.Fatalf("Node-compatible name did not match: %s", name)
		}
	}
}

func TestHardLimitValidation(t *testing.T) {
	valid := DefaultLimits()
	if !validLimits(valid) {
		t.Fatal("default limits are invalid")
	}
	for _, mutate := range []func(*Limits){
		func(l *Limits) { l.MaxFiles = 4097 },
		func(l *Limits) { l.MaxEvents = 10_000_001 },
		func(l *Limits) { l.MaxLineBytes = 1024*1024 + 1 },
		func(l *Limits) { l.MaxTotalBytes = 4*1024*1024*1024 + 1 },
		func(l *Limits) { l.MaxDepth = 129 },
	} {
		limits := valid
		mutate(&limits)
		if validLimits(limits) {
			t.Fatalf("hard limit accepted: %+v", limits)
		}
	}
}

func TestScannerLineLimitIsStable(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "audit-chain-2026-09-13.jsonl"), []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxLineBytes = 16
	if _, err := VerifyDirectory(context.Background(), directory, limits); !errors.Is(err, ErrChainLimit) {
		t.Fatalf("error = %v, want ErrChainLimit", err)
	}
}
