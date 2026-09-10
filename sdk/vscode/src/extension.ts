import * as vscode from 'vscode';
import { BrokerClient, OperationRequest, redact } from './client';

let client: BrokerClient | null = null;
let statusBarItem: vscode.StatusBarItem | null = null;
let outputChannel: vscode.OutputChannel | null = null;
let refreshTimer: NodeJS.Timeout | null = null;

function log(message: string): void {
  outputChannel?.appendLine(`[${new Date().toISOString()}] ${redact(message)}`);
}

function getClient(): BrokerClient {
  if (client) return client;
  const config = vscode.workspace.getConfiguration('secretBroker');
  for (const name of ['endpoint', 'clientCert', 'clientKey', 'caCert']) {
    const inspected = config.inspect(name);
    if (inspected?.workspaceValue !== undefined || inspected?.workspaceFolderValue !== undefined) {
      throw new Error(`secretBroker.${name} must be configured at machine scope`);
    }
  }
  client = new BrokerClient({
    endpoint: config.get<string>('endpoint') || 'https://127.0.0.1:8443',
    clientCert: config.get<string>('clientCert') || '',
    clientKey: config.get<string>('clientKey') || '',
    caCert: config.get<string>('caCert') || '',
  });
  return client;
}

async function refreshStatusBar(): Promise<void> {
  if (!statusBarItem) return;
  try {
    const health = await getClient().health();
    statusBarItem.text = `$(shield) Broker: ${health.version}`;
    statusBarItem.tooltip = 'Secret Broker is reachable';
  } catch (error) {
    statusBarItem.text = '$(shield) Broker: unavailable';
    statusBarItem.tooltip = redact(String(error));
  }
}

async function promptOperation(): Promise<OperationRequest | null> {
  const provider = await vscode.window.showInputBox({ prompt: 'Provider manifest ID (for example: github)' });
  if (!provider) return null;
  const operationId = await vscode.window.showInputBox({ prompt: 'Allowlisted operation ID (for example: repo.read)' });
  if (!operationId) return null;
  const accountRef = await vscode.window.showInputBox({ prompt: 'Broker account reference' });
  if (!accountRef) return null;
  const environment = await vscode.window.showQuickPick(
    ['development', 'staging', 'production'] as const,
    { placeHolder: 'Target environment' },
  );
  if (!environment) return null;
  const rawParameters = await vscode.window.showInputBox({
    prompt: 'Typed parameters as JSON. The provider schema is enforced by the Broker.', value: '{}',
  });
  if (rawParameters === undefined) return null;
  let typedParameters: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(rawParameters);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('parameters must be an object');
    typedParameters = parsed as Record<string, unknown>;
  } catch (error) {
    vscode.window.showErrorMessage(`Invalid parameters: ${redact(String(error))}`);
    return null;
  }
  return {
    provider, operation_id: operationId, account_ref: accountRef,
    environment: environment as OperationRequest['environment'], typed_parameters: typedParameters,
  };
}

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel('Secret Broker');
  context.subscriptions.push(outputChannel);
  const config = vscode.workspace.getConfiguration('secretBroker');
  if (config.get<boolean>('statusBarEnabled', true)) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'secretBroker.health';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    void refreshStatusBar();
    refreshTimer = setInterval(() => void refreshStatusBar(), 60_000);
  }

  context.subscriptions.push(
    vscode.commands.registerCommand('secretBroker.health', async () => {
      try {
        const health = await getClient().health();
        vscode.window.showInformationMessage(`Broker is reachable (v${health.version})`);
      } catch (error) {
        vscode.window.showErrorMessage(redact(String(error)));
      }
    }),
    vscode.commands.registerCommand('secretBroker.list', async () => {
      try {
        const items = await getClient().list();
        await vscode.window.showQuickPick(items.map((item) => `${item.name} (${item.type})`), {
          placeHolder: 'Visible secret metadata (values are never returned)',
        });
      } catch (error) {
        vscode.window.showErrorMessage(redact(String(error)));
      }
    }),
    vscode.commands.registerCommand('secretBroker.operation.create', async () => {
      const request = await promptOperation();
      if (!request) return;
      try {
        const operation = await getClient().createOperation(request);
        vscode.window.showInformationMessage(`Operation ${operation.id}: ${operation.status}`);
        log(`Created ${operation.provider}/${operation.operation_id}: ${operation.id}`);
      } catch (error) {
        vscode.window.showErrorMessage(redact(String(error)));
      }
    }),
  );
  log('Extension activated');
}

export function deactivate(): void {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = null;
  client?.logout().catch(() => undefined);
  client = null;
  statusBarItem = null;
}
