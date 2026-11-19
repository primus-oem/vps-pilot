import * as vscode from 'vscode';
import { createServerConfiguration, validateServerBinary } from './serverConfiguration';

export function activate(context: vscode.ExtensionContext): void {
  const definitionsChanged = new vscode.EventEmitter<void>();
  const configurationChanged = vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration('vpsPilot.binaryPath')) {
      definitionsChanged.fire();
    }
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

  context.subscriptions.push(provider, definitionsChanged, configurationChanged);
}

export function deactivate(): void {}