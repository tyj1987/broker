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

	"github.com/tyj1987/broker/core/githubsigner"
	"github.com/tyj1987/broker/core/internal/socketactivation"
)

const (
	configPath = "/etc/secret-broker/providers/github-signer.json"
	brokerUser = "broker"
	socketName = "github-signer"
	socketPath = "/run/secret-broker-github-signer/signer.sock"
)

var errBackendUnavailable = errors.New("signing backend is unavailable")

type dependencies struct {
	loadConfig func(string) (githubsigner.ServiceConfig, error)
	lookupUID  func(string) (uint32, error)
	newPeer    func(uint32) (githubsigner.PeerAuthorizer, error)
	newSigner  func(context.Context, githubsigner.ServiceConfig) (githubsigner.DigestSigner, error)
	listener   func(string, string) (net.Listener, error)
	serve      func(context.Context, *githubsigner.Server, net.Listener) error
}

func defaultDependencies() dependencies {
	return dependencies{
		loadConfig: githubsigner.LoadServiceConfigFile,
		lookupUID:  lookupUID,
		newPeer:    githubsigner.NewOSPeerAuthorizer,
		newSigner: func(context.Context, githubsigner.ServiceConfig) (githubsigner.DigestSigner, error) {
			return nil, errBackendUnavailable
		},
		listener: socketactivation.Listener,
		serve: func(ctx context.Context, server *githubsigner.Server, listener net.Listener) error {
			return server.Serve(ctx, listener)
		},
	}
}

func run(ctx context.Context, args []string, deps dependencies) (int, string) {
	flags := flag.NewFlagSet("secret-broker-github-signer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectedConfig := flags.String("config", "", "fixed non-secret service configuration")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *selectedConfig != configPath {
		return 64, "usage_invalid"
	}
	if ctx == nil || deps.loadConfig == nil || deps.lookupUID == nil || deps.newPeer == nil || deps.newSigner == nil ||
		deps.listener == nil || deps.serve == nil {
		return 70, "runtime_invalid"
	}
	config, err := deps.loadConfig(*selectedConfig)
	if err != nil {
		return 78, "config_invalid"
	}
	uid, err := deps.lookupUID(brokerUser)
	if err != nil {
		return 78, "peer_identity_unavailable"
	}
	peer, err := deps.newPeer(uid)
	if err != nil {
		return 78, "peer_identity_unavailable"
	}
	bindings, err := githubsigner.NewBindingSet(config.Bindings)
	if err != nil {
		return 78, "config_invalid"
	}
	signer, err := deps.newSigner(ctx, config)
	if err != nil || signer == nil {
		return 78, "signing_identity_unavailable"
	}
	server, err := githubsigner.NewServer(signer, bindings, peer, config.AuthorityGenerationSHA256)
	if err != nil {
		return 70, "runtime_invalid"
	}
	listener, err := deps.listener(socketName, socketPath)
	if err != nil {
		return 78, "socket_activation_invalid"
	}
	defer listener.Close()
	if err = deps.serve(ctx, server, listener); err != nil {
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
	code, reason := run(ctx, os.Args[1:], defaultDependencies())
	if reason != "" {
		_, _ = fmt.Fprintf(os.Stderr, "github_signer_start_failed=%s\n", reason)
	}
	os.Exit(code)
}
