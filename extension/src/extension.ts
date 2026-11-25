import * as vscode from 'vscode';
import { InventoryTreeProvider } from './inventoryView';
import { openDeploymentPanel } from './deploymentView';
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
    const binaryPath = createServerConfiguration(vscode.workspace.getConfiguration('vpsPilot').get<string>('binaryPath')).command;
    openDeploymentPanel(context, binaryPath);
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