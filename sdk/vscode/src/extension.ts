// Secret Broker VS Code extension — command registrations.
import * as vscode from 'vscode';
import { BrokerClient, BrokerError, BrokerConnectionError, redact } from './client';

let client: BrokerClient | null = null;
let statusBarItem: vscode.StatusBarItem | null = null;
let outputChannel: vscode.OutputChannel | null = null;

function log(msg: string, redactIt = true): void {
  if (!outputChannel) return;
  const text = redactIt ? redact(msg) : msg;
  outputChannel.appendLine(`[${new Date().toISOString()}] ${text}`);
}

function getClient(): BrokerClient {
  if (client) return client;
  const cfg = vscode.workspace.getConfiguration('secretBroker');
  const endpoint = cfg.get<string>('endpoint') || 'https://127.0.0.1:8443';
  const clientCert = cfg.get<string>('clientCert') || '';
  const clientKey = cfg.get<string>('clientKey') || '';
  const caCert = cfg.get<string>('caCert') || '';
  client = new BrokerClient({ endpoint, clientCert, clientKey, caCert });
  return client;
}

function showSecretInUI(name: string, value: string, redactInUI: boolean): void {
  if (redactInUI) {
    vscode.window.showInformationMessage(
      `Secret '${name}' resolved (${value.length} chars). Use 'Reveal' button to view.`,
      'Copy to Clipboard',
      'Reveal'
    ).then((choice) => {
      if (choice === 'Copy to Clipboard') {
        vscode.env.clipboard.writeText(value);
        vscode.window.showInformationMessage(`Copied '${name}' to clipboard (will be cleared in 60s).`);
        setTimeout(() => vscode.env.clipboard.writeText(''), 60_000);
      } else if (choice === 'Reveal') {
        vscode.window.showInputBox({
          prompt: 'Type YES to reveal the secret value',
          validateInput: (v) => (v === 'YES' ? null : 'Type exactly YES to confirm'),
        }).then((confirm) => {
          if (confirm === 'YES') {
            vscode.window.showInformationMessage(`Secret '${name}': ${value}`, 'OK');
            // Clear from memory after 30s
            setTimeout(() => {}, 30_000);
          }
        });
      }
    });
  } else {
    vscode.window.showInformationMessage(`Secret '${name}': ${value}`);
  }
}

async function refreshStatusBar(): Promise<void> {
  if (!statusBarItem) return;
  try {
    const h = await getClient().health();
    statusBarItem.text = `$(shield) Broker: ${h.version}`;
    statusBarItem.tooltip = `Broker healthy (v${h.version})`;
  } catch (e) {
    statusBarItem.text = `$(shield) Broker: down`;
    statusBarItem.tooltip = redact(String(e));
  }
}

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel('Secret Broker');

  // Status bar
  const cfg = vscode.workspace.getConfiguration('secretBroker');
  if (cfg.get<boolean>('statusBarEnabled', true)) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'secretBroker.health';
    context.subscriptions.push(statusBarItem);
    statusBarItem.show();
    refreshStatusBar();
    setInterval(refreshStatusBar, 60_000);  // every 60s
  }

  // 7 commands
  context.subscriptions.push(
    vscode.commands.registerCommand('secretBroker.health', async () => {
      try {
        const h = await getClient().health();
        vscode.window.showInformationMessage(`Broker healthy (v${h.version})`);
      } catch (e) {
        vscode.window.showErrorMessage(redact(String(e)));
      }
    }),

    vscode.commands.registerCommand('secretBroker.list', async () => {
      try {
        const items = await getClient().list();
        if (items.length === 0) {
          vscode.window.showInformationMessage('No secrets visible to this client');
          return;
        }
        const picks = items.map((s) => `${s.name} (${s.type})`);
        const choice = await vscode.window.showQuickPick(picks, { placeHolder: 'Select a secret to resolve' });
        if (!choice) return;
        const name = choice.split(' ')[0];
        await vscode.commands.executeCommand('secretBroker.get', name);
      } catch (e) {
        vscode.window.showErrorMessage(redact(String(e)));
      }
    }),

    vscode.commands.registerCommand('secretBroker.get', async (nameArg?: string) => {
      const name = nameArg || await vscode.window.showInputBox({ prompt: 'Secret name' });
      if (!name) return;
      try {
        const value = await getClient().getSecret(name);
        const redactInUI = cfg.get<boolean>('redactInUI', true);
        showSecretInUI(name, value, redactInUI);
        log(`Resolved secret: ${name} (${value.length} chars)`, true);
      } catch (e) {
        vscode.window.showErrorMessage(redact(String(e)));
      }
    }),

    vscode.commands.registerCommand('secretBroker.resolve', async () => {
      const namesRaw = await vscode.window.showInputBox({
        prompt: 'Comma-separated secret names to resolve into env',
        placeHolder: 'github.pat, openai.key',
      });
      if (!namesRaw) return;
      const names = namesRaw.split(',').map((s) => s.trim()).filter(Boolean);
      try {
        const env = await getClient().resolveBulk(names);
        // Build a .env string
        const envText = Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n');
        const doc = await vscode.workspace.openTextDocument({ content: envText, language: 'dotenv' });
        await vscode.window.showTextDocument(doc, { preview: false });
        log(`Resolved ${names.length} secrets to .env document`, true);
      } catch (e) {
        vscode.window.showErrorMessage(redact(String(e)));
      }
    }),

    vscode.commands.registerCommand('secretBroker.proxy', async () => {
      const service = await vscode.window.showInputBox({ prompt: 'Service name (e.g. github)', value: 'github' });
      if (!service) return;
      const method = await vscode.window.showInputBox({ prompt: 'HTTP method', value: 'GET' });
      if (!method) return;
      const subPath = await vscode.window.showInputBox({ prompt: 'Sub-path (e.g. /repos/owner/repo)' });
      if (!subPath) return;
      try {
        const r = await getClient().proxy(service, method, subPath);
        const body = typeof r.body === 'string' ? r.body : JSON.stringify(r.body, null, 2);
        const doc = await vscode.workspace.openTextDocument({ content: body });
        await vscode.window.showTextDocument(doc, { preview: true });
        log(`Proxied ${method} ${service}${subPath} -> ${r.status}`, true);
      } catch (e) {
        vscode.window.showErrorMessage(redact(String(e)));
      }
    }),

    vscode.commands.registerCommand('secretBroker.sshExec', async () => {
      const target = await vscode.window.showInputBox({ prompt: 'SSH target (user@host[:port])' });
      if (!target) return;
      const command = await vscode.window.showInputBox({ prompt: 'Command to run on remote host' });
      if (!command) return;
      try {
        const r = await getClient().sshExec(target, command);
        if (outputChannel) {
          outputChannel.show();
          log(`ssh_exec ${target} -> exit=${r.exitCode}`, true);
          if (r.stdout) log(`stdout:\n${r.stdout}`, true);
          if (r.stderr) log(`stderr:\n${r.stderr}`, true);
        }
      } catch (e) {
        vscode.window.showErrorMessage(redact(String(e)));
      }
    }),

    vscode.commands.registerCommand('secretBroker.login', async () => {
      const username = await vscode.window.showInputBox({ prompt: 'Username' });
      if (!username) return;
      const password = await vscode.window.showInputBox({ prompt: 'Password', password: true });
      if (!password) return;
      try {
        const r = await getClient().login(username, password);
        if (r.mfa_required && r.mfa_token) {
          const code = await vscode.window.showInputBox({ prompt: 'MFA code (TOTP)' });
          if (code) {
            await getClient().login(username, password, r.mfa_token, code);
          }
        }
        vscode.window.showInformationMessage('Login successful');
      } catch (e) {
        vscode.window.showErrorMessage(redact(String(e)));
      }
    })
  );

  log('Secret Broker extension activated', true);
}

export function deactivate(): void {
  if (client) {
    client.logout().catch(() => undefined);
    client = null;
  }
  if (statusBarItem) {
    statusBarItem.dispose();
    statusBarItem = null;
  }
}
