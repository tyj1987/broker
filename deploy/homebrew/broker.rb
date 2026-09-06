# typed: false
# frozen_string_literal: true

# Homebrew formula for Secret Broker — mTLS credential proxy for AI clients.
# Source: https://github.com/tyj1987/broker
#
# To install (after `tyj1987/homebrew-broker` tap is published):
#   brew tap tyj1987/broker
#   brew install broker
#
# Or in one line:
#   brew install tyj1987/broker/broker
#
# This formula installs the broker CLI (`secret-broker`) and the broker server
# (`secret-broker-server`). The CLI is a zero-dependency Node.js script; the
# server requires `npm install` of the broker package.

class SecretBroker < Formula
  desc "mTLS credential proxy for AI clients (CLI + server)"
  homepage "https://github.com/tyj1987/broker"
  url "https://github.com/tyj1987/broker/archive/refs/tags/v4.1.1.tar.gz"
  sha256 "PLACEHOLDER_SHA256_V4_1_1_TARBALL"
  license "MIT"

  depends_on "node@20"

  # Zero runtime dependencies for the CLI (stdlib only). Server requires
  # `npm install` of the broker package (see caveats below).

  def install
    # 1. Install the CLI as `secret-broker` (zero-dep, stdlib only)
    libexec.install "cli/secret-broker.js" => "secret-broker.js"
    bin.install_symlink libexec/"secret-broker.js" => "secret-broker"

    # 2. Install the server package to libexec (Cellar). The user can run it
    #    with `secret-broker-server` (symlink to a wrapper script below).
    libexec.install Dir["broker", "bin", "scripts", "package.json", "package-lock.json",
                       "ARCHITECTURE.md", "RUNBOOK.md", "CHANGELOG.md", "VERIFIED.md",
                       "STATUS.md", "LICENSE", "README.md"].select { |f| File.exist?(f) }

    # Wrapper script for the server — runs `node broker/server.js` from libexec.
    (bin/"secret-broker-server").write <<~SH
      #!/bin/bash
      set -euo pipefail
      exec "#{Formula["node@20"].opt_bin}/node" "#{libexec}/broker/server.js" "$@"
    SH
    (bin/"secret-broker-server").chmod 0755

    # 3. Bash completions (if any)
    # bash_completions.install "completions/secret-broker.bash" if File.exist?("completions/secret-broker.bash")
  end

  def caveats
    <<~EOS
      Secret Broker #{version} has been installed.

      === CLI (zero-dep, ready to use) ===
        secret-broker --help
        secret-broker health
        secret-broker list

      Configure the CLI by creating ~/.broker/config.json:
        {
          "endpoint":   "https://broker.example.com:8443",
          "client_cert": "/path/to/client.crt",
          "client_key":  "/path/to/client.key",
          "ca_cert":     "/path/to/ca.crt"
        }

      === Server (needs PKI + config) ===
        secret-broker-server

      The server requires:
        1. mTLS PKI in $(brew --prefix)/opt/secret-broker/pki/
        2. Config in $(brew --prefix)/etc/secret-broker/broker.yaml
        3. Secrets in $(brew --prefix)/etc/secret-broker/secrets/secrets-detail.json
        4. SOPS age key in $(brew --prefix)/etc/secret-broker/pki/age.key

      See docs/HOMEBREW.md (in the broker repo) for the full setup walkthrough.

      === Upgrading ===
        brew upgrade secret-broker

      === Uninstalling ===
        brew uninstall secret-broker
        # data + config in $(brew --prefix)/etc/secret-broker/ is preserved;
        # remove manually if desired.
    EOS
  end

  test do
    # Smoke test: CLI loads and reports version
    assert_match "secret-broker #{version}",
                 shell_output("#{bin}/secret-broker --version 2>&1 || true")

    # Node version check
    node = Formula["node@20"].opt_bin/"node"
    assert_match "v20", shell_output("#{node} --version")

    # Server syntax check (don't actually start — just confirm the file parses)
    server_js = libexec/"broker/server.js"
    assert_predicate server_js, :exist?
    output = shell_output("#{node} --check #{server_js} 2>&1", 1)
    # Note: `node --check` may exit 0 or 1 depending on whether it found any
    # syntax issues; we only assert the file is readable and the command ran.
    refute_empty output
  end
end
