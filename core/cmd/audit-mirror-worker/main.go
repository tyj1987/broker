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

	"github.com/tyj1987/broker/core/auditmirror"
	"github.com/tyj1987/broker/core/auditmirrorworker"
	"github.com/tyj1987/broker/core/internal/socketactivation"
)

const (
	configPath = "/etc/secret-broker/audit/mirror-worker.json"
	workerUser = "broker-audit-mirror"
	storeUser  = "broker-audit-store"
	socketName = "audit-mirror"
	socketPath = auditmirror.DefaultSocketPath
)

type boundBackend interface {
	auditmirror.Client
	Binding() auditmirror.Binding
}

type dependencies struct {
	loadConfig func(string) (auditmirrorworker.Config, error)
	lookupUID  func(string) (uint32, error)
	currentUID func() uint32
	newPeer    func(uint32) (auditmirror.PeerAuthorizer, error)
	newRuntime func(context.Context, auditmirrorworker.Config, auditmirrorworker.COSClientFactory) (boundBackend, error)
	factory    auditmirrorworker.COSClientFactory
	listener   func(string, string) (net.Listener, error)
	serve      func(context.Context, *auditmirror.Server, net.Listener) error
}

func defaultDependencies() dependencies {
	return dependencies{
		loadConfig: auditmirrorworker.LoadConfigFile,
		lookupUID:  lookupUID,
		currentUID: currentEUID,
		newPeer:    auditmirror.NewOSPeerAuthorizer,
		newRuntime: func(ctx context.Context, config auditmirrorworker.Config, factory auditmirrorworker.COSClientFactory) (boundBackend, error) {
			return auditmirrorworker.NewRuntime(ctx, config, factory)
		},
		factory:  auditmirrorworker.UnavailableCOSClientFactory{},
		listener: socketactivation.Listener,
		serve: func(ctx context.Context, server *auditmirror.Server, listener net.Listener) error {
			return server.Serve(ctx, listener)
		},
	}
}

func run(ctx context.Context, args []string, deps dependencies) (int, string) {
	flags := flag.NewFlagSet("secret-broker-audit-mirror-worker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectedConfig := flags.String("config", "", "fixed non-secret worker configuration")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *selectedConfig != configPath {
		return 64, "usage_invalid"
	}
	if ctx == nil || deps.loadConfig == nil || deps.lookupUID == nil || deps.currentUID == nil || deps.newPeer == nil ||
		deps.newRuntime == nil || deps.factory == nil || deps.listener == nil || deps.serve == nil {
		return 70, "runtime_invalid"
	}
	config, err := deps.loadConfig(*selectedConfig)
	if err != nil {
		return 78, "config_invalid"
	}
	workerUID, err := deps.lookupUID(workerUser)
	if err != nil || workerUID == 0 || deps.currentUID() != workerUID {
		return 78, "worker_identity_unavailable"
	}
	storeUID, err := deps.lookupUID(storeUser)
	if err != nil || storeUID == 0 || storeUID == workerUID {
		return 78, "peer_identity_unavailable"
	}
	peer, err := deps.newPeer(storeUID)
	if err != nil || peer == nil {
		return 78, "peer_identity_unavailable"
	}
	backend, err := deps.newRuntime(ctx, config, deps.factory)
	if err != nil || backend == nil {
		return 78, "cloud_identity_unavailable"
	}
	server, err := auditmirror.NewServer(backend.Binding(), backend, peer)
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
		_, _ = fmt.Fprintf(os.Stderr, "audit_mirror_worker_start_failed=%s\n", reason)
	}
	os.Exit(code)
}
