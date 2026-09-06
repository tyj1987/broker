// broker-desktop/src/index.tsx
// Phase 1: minimal "Hello broker" frontend
// Phase 2-6: dashboard, service list, health monitor, alert history, mTLS enroll UI, TOTP setup
//
// Tauri 2.x frontend entry. See docs/DESIGN-TAURI-DESKTOP.md §5 for the full
// feature set and §6 for the phased rollout.

import { render } from "solid-js/web";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");

function App() {
  return (
    <div class="flex min-h-screen flex-col bg-slate-900 text-slate-100">
      <header class="flex items-center justify-between border-b border-slate-700 bg-slate-800 px-6 py-3">
        <h1 class="text-xl font-semibold">🔐 Secret Broker</h1>
        <span class="text-sm text-slate-400">desktop client (alpha)</span>
      </header>

      <main class="flex-1 px-6 py-8">
        <div class="mx-auto max-w-2xl rounded-lg border border-slate-700 bg-slate-800 p-6 shadow-xl">
          <h2 class="text-lg font-semibold">Hello broker</h2>
          <p class="mt-2 text-sm text-slate-300">
            Tauri 2.x scaffold is up. Phase 2-6 will add:
          </p>
          <ul class="mt-4 space-y-1 text-sm text-slate-300 list-disc list-inside">
            <li>mTLS client cert enrollment (one-click via CSR + QR)</li>
            <li>REST + WebSocket broker connection (auto-reconnect)</li>
            <li>System tray icon with real-time health</li>
            <li>Native notifications for alerts (severity ≥ medium)</li>
            <li>Auto-update via Tauri updater (ed25519 signed)</li>
            <li>Multi-broker support (dev + prod + staging)</li>
          </ul>
          <p class="mt-4 text-xs text-slate-400">
            See <code class="rounded bg-slate-900 px-1">docs/DESIGN-TAURI-DESKTOP.md</code> for the full spec.
          </p>
        </div>
      </main>
    </div>
  );
}

render(() => <App />, root);
