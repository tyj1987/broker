# Isolated browser worker core

This module enforces the application boundary for reviewed web adapters. It
accepts only typed operations, creates a non-persistent browser context for one
operation, blocks service workers and downloads, applies an exact HTTPS-origin
allowlist, filters returned data, and closes the context on every outcome.

It deliberately contains no provider login adapter or production launcher yet.
Provider selectors and URLs must be versioned source code, not request fields.
Container-level DNS/IP egress enforcement, credential injection, CAPTCHA/user
handoff, real Aliyun/Tencent contract tests and an ephemeral runtime image are
required before this worker can be enabled in production.

`BrowserBrokerClient` implements the signed, single-use lease exchange without
loading any private key. A production launcher must inject a signer backed by a
non-exportable workload key or short-lived workload identity. Private keys are
not accepted through environment variables or command-line arguments. Worker
capabilities are exact grants over provider, operation, account and environment.
