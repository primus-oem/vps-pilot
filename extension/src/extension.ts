import * as vscode from 'vscode';
import { execFile } from 'node:child_process';
import { InventoryTreeProvider } from './inventoryView';
import { createServerConfiguration, validateServerBinary } from './serverConfiguration';

export function activate(context: vscode.ExtensionContext): void {
  const definitionsChanged = new vscode.EventEmitter<void>();
  const inventory = new InventoryTreeProvider(() => {
    const binaryPath = vscode.workspace.getConfiguration('vpsPilot').get<string>('binaryPath');
    return createServerConfiguration(binaryPath).command;
  });
  const configurationChanged = vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration('vpsPilot.binaryPath')) {
      definitionsChanged.fire();
      inventory.refresh();
    }
  });
  const inventoryView = vscode.window.createTreeView('vpsPilot.inventory', { treeDataProvider: inventory });
  const refreshInventory = vscode.commands.registerCommand('vpsPilot.refreshInventory', () => inventory.refresh());
  const openWorkflow = vscode.commands.registerCommand('vpsPilot.openDeploymentWorkflow', async () => {
    const appList = await runCoreText(createServerConfiguration(vscode.workspace.getConfiguration('vpsPilot').get<string>('binaryPath')).command, ['app', 'list']);
    const applications = appList.split(/\r?\n/).filter(Boolean).map((line) => line.split('\t')[0]).filter(Boolean);
    if (applications.length === 0) {
      void vscode.window.showWarningMessage('No VPS Pilot applications are imported. Import a manifest with the CLI first.');
      return;
    }
    const application = await vscode.window.showQuickPick(applications, { title: 'VPS Pilot deployment', placeHolder: 'Select application' });
    if (!application) {
      return;
    }
    const environment = await vscode.window.showInputBox({
      title: 'VPS Pilot deployment',
      prompt: `Environment for ${application}`,
      value: 'staging',
      ignoreFocusOut: true,
    });
    if (!environment) {
      return;
    }
    const services = await vscode.window.showInputBox({
      title: 'VPS Pilot deployment',
      prompt: `Comma-separated services for ${application}`,
      value: '',
      ignoreFocusOut: true,
    });
    if (services === undefined) {
      return;
    }
    const action = await vscode.window.showQuickPick(
      ['Plan', 'Plan + Preflight', 'Plan + Preflight + Terminal Approval'],
      { title: 'VPS Pilot deployment', placeHolder: 'Choose workflow action' },
    );
    if (!action) {
      return;
    }
    const terminal = vscode.window.createTerminal({ name: 'VPS Pilot Deployment' });
    const binary = createServerConfiguration(vscode.workspace.getConfiguration('vpsPilot').get<string>('binaryPath')).command;
    const planCommand = `${shellQuote(binary)} app plan ${shellQuote(application)} ${shellQuote(environment)} ${shellQuote(services)}`
      + ' | tee /tmp/vps-pilot-plan.json';
    terminal.sendText(planCommand, true);
    terminal.sendText('echo "Plan preview created. Copy its plan_digest for preflight/approval."', true);
    if (action !== 'Plan') {
      terminal.sendText(`echo "Run: ${binary} app preflight <plan-digest>"`, true);
    }
    if (action === 'Plan + Preflight + Terminal Approval') {
      terminal.sendText(`echo "Then run: ${binary} app approve <plan-digest> && ${binary} app deploy <plan-digest>"`, true);
    }
    terminal.show();
  });

  const provider = vscode.lm.registerMcpServerDefinitionProvider('vps-pilot.mcp', {
    onDidChangeMcpServerDefinitions: definitionsChanged.event,
    provideMcpServerDefinitions: () => {
      const binaryPath = vscode.workspace.getConfiguration('vpsPilot').get<string>('binaryPath');
      const configuration = createServerConfiguration(binaryPath);
      const validationError = validateServerBinary(configuration.command);
      if (validationError) {
        void vscode.window.showErrorMessage(`VPS Pilot core could not start: ${validationError}`);
        return [];
      }
      return [new vscode.McpStdioServerDefinition(
        configuration.label,
        configuration.command,
        configuration.args,
        undefined,
        configuration.version,
      )];
    },
  });

  context.subscriptions.push(provider, definitionsChanged, configurationChanged, inventoryView, refreshInventory, openWorkflow, inventory);
}

export function deactivate(): void {}

function runCoreText(binary: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(binary, args, { encoding: 'utf8', timeout: 10000, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr.trim() || error.message));
        return;
      }
      resolve(stdout);
    });
  });
}

function shellQuote(value: string): string {
  return `'` + value.replace(/'/g, `'\\''`) + `'`;
}