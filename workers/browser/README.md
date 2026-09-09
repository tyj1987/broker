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
