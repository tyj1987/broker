package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/internal/socketactivation"
)

const (
	signerConfigPath = "/etc/secret-broker/audit/signer.json"
	signerUser       = "broker-audit-signer"
	exporterUser     = "broker-audit-exporter"
	signerSocketName = "audit-signer"
	signerSocketPath = "/run/secret-broker-audit-anchor/signer.sock"
)

var errSigningAuthorityUnavailable = errors.New("audit signing authority is unavailable")

type signerDependencies struct {
	loadConfig  func(string) (auditanchor.SignerServiceConfig, error)
	lookupUID   func(string) (uint32, error)
	currentUID  func() uint32
	newPeer     func(uint32) (auditanchor.PeerAuthorizer, error)
	newBackends func(context.Context, auditanchor.SignerServiceConfig) (auditanchor.Signer, auditanchor.AnchorAuthorizer, error)
	listener    func(string, string) (net.Listener, error)
	serve       func(context.Context, *auditanchor.Server, net.Listener) error
}

func defaultSignerDependencies() signerDependencies {
	return signerDependencies{
		loadConfig: auditanchor.LoadSignerServiceConfigFile,
		lookupUID:  lookupUID,
		currentUID: currentEUID,
		newPeer:    auditanchor.NewOSPeerAuthorizer,
		newBackends: func(context.Context, auditanchor.SignerServiceConfig) (auditanchor.Signer, auditanchor.AnchorAuthorizer, error) {
			return nil, nil, errSigningAuthorityUnavailable
		},
		listener: socketactivation.Listener,
		serve: func(ctx context.Context, server *auditanchor.Server, listener net.Listener) error {
			return server.Serve(ctx, listener)
		},
	}
}

func runAuditSigner(ctx context.Context, args []string, dependencies signerDependencies) (int, string) {
	flags := flag.NewFlagSet("secret-broker-audit-signer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectedConfig := flags.String("config", "", "fixed non-secret service configuration")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *selectedConfig != signerConfigPath {
		return 64, "usage_invalid"
	}
	if ctx == nil || dependencies.loadConfig == nil || dependencies.lookupUID == nil ||
		dependencies.currentUID == nil || dependencies.newPeer == nil || dependencies.newBackends == nil ||
		dependencies.listener == nil || dependencies.serve == nil {
		return 70, "runtime_invalid"
	}
	config, err := dependencies.loadConfig(*selectedConfig)
	if err != nil {
		return 78, "config_invalid"
	}
	config, err = auditanchor.ValidateSignerServiceConfig(config)
	if err != nil {
		return 78, "config_invalid"
	}
	signerUID, err := dependencies.lookupUID(signerUser)
	if err != nil || signerUID == 0 || dependencies.currentUID() != signerUID {
		return 78, "signer_identity_unavailable"
	}
	exporterUID, err := dependencies.lookupUID(exporterUser)
	if err != nil || exporterUID == 0 || exporterUID == signerUID {
		return 78, "peer_identity_unavailable"
	}
	peer, err := dependencies.newPeer(exporterUID)
	if err != nil || peer == nil {
		return 78, "peer_identity_unavailable"
	}
	signer, anchors, err := dependencies.newBackends(ctx, config)
	if err != nil || signer == nil || anchors == nil {
		return 78, "signing_authority_unavailable"
	}
	server, err := auditanchor.NewServer(config.Anchor, signer, anchors, peer)
	if err != nil {
		return 70, "runtime_invalid"
	}
	listener, err := dependencies.listener(signerSocketName, signerSocketPath)
	if err != nil || listener == nil {
		return 78, "socket_activation_invalid"
	}
	defer listener.Close()
	if err = dependencies.serve(ctx, server, listener); err != nil {
		if ctx.Err() != nil {
			return 0, ""
		}
		return 70, "service_failed"
	}
	return 0, ""
}

func lookupUID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil || account == nil {
		return 0, errors.New("identity unavailable")
	}
	value, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || value == 0 {
		return 0, errors.New("identity unavailable")
	}
	return uint32(value), nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, reason := runAuditSigner(ctx, os.Args[1:], defaultSignerDependencies())
	if reason != "" {
		_, _ = fmt.Fprintf(os.Stderr, "audit_signer_start_failed=%s\n", reason)
	}
	os.Exit(code)
}
