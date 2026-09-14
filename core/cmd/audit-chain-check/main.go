package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tyj1987/broker/core/auditchain"
)

func run(
	ctx context.Context,
	args []string,
	getenv func(string) string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if ctx == nil || getenv == nil || stdout == nil || stderr == nil || len(args) != 0 {
		return 64
	}
	directory := getenv("AUDIT_DIR")
	if directory == "" || !filepath.IsAbs(directory) {
		_, _ = fmt.Fprintln(stderr, "audit chain check requires an absolute AUDIT_DIR")
		return 64
	}
	state, err := auditchain.VerifyDirectory(ctx, directory, auditchain.DefaultLimits())
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "audit_chain_verified=no")
		return 65
	}
	_, _ = fmt.Fprintf(stdout, "audit_chain_verified=yes files=%d events=%d\n", state.Files, state.Count)
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}
