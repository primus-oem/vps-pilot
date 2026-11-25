import { execFile } from 'node:child_process';
import * as vscode from 'vscode';

export function openDeploymentPanel(context: vscode.ExtensionContext, binaryPath: string): void {
  const panel = vscode.window.createWebviewPanel(
    'vpsPilotDeployment',
    'VPS Pilot Deployment',
    vscode.ViewColumn.One,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')],
    },
  );
  panel.webview.html = htmlFor(panel.webview);

  panel.webview.onDidReceiveMessage(async (message: unknown) => {
    if (!isRecord(message) || typeof message.command !== 'string') {
      return;
    }
    if (message.command === 'refresh') {
      try {
        const apps = await runCore(binaryPath, ['app', 'list']);
        await panel.webview.postMessage({ command: 'applications', value: safeText(apps).slice(0, 10000) });
      } catch (error) {
        await panel.webview.postMessage({ command: 'error', value: errorText(error) });
      }
      return;
    }
    if (message.command === 'plan'
      && typeof message.application === 'string'
      && typeof message.environment === 'string'
      && typeof message.services === 'string') {
      try {
        const result = await runCore(binaryPath, [
          'app', 'plan', message.application, message.environment,
          message.services.split(',').map((item) => item.trim()).filter(Boolean).join(','),
        ]);
        await panel.webview.postMessage({ command: 'plan', value: safeText(result).slice(0, 100000) });
      } catch (error) {
        await panel.webview.postMessage({ command: 'error', value: errorText(error) });
      }
    }
  });
}

function htmlFor(webview: vscode.Webview): string {
  const nonce = Math.random().toString(36).slice(2);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style nonce="${nonce}">
body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 16px; }
label { display:block; margin-top:10px; } input { width:min(720px,100%); box-sizing:border-box; }
button { margin-top:12px; margin-right:8px; } pre { max-height:60vh; overflow:auto; padding:12px; border:1px solid var(--vscode-widget-border); white-space:pre-wrap; }
.error { color:var(--vscode-errorForeground); } .muted { color:var(--vscode-descriptionForeground); }
</style>
</head>
<body>
<h2>VPS Pilot Deployment</h2>
<p class="muted">Only review and approval-bound typed operations are supported. Secrets are never entered here.</p>
<label>Application <input id="application" autocomplete="off"></label>
<label>Environment <input id="environment" value="staging"></label>
<label>Services <input id="services" placeholder="api,worker,frontend"></label>
<button id="list">Refresh applications</button>
<button id="plan">Create preview plan</button>
<pre id="applications"></pre>
<pre id="output"></pre>
<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
document.getElementById('list').onclick = () => vscode.postMessage({command:'refresh'});
document.getElementById('plan').onclick = () => vscode.postMessage({
  command:'plan',
  application:document.getElementById('application').value.trim(),
  environment:document.getElementById('environment').value.trim(),
  services:document.getElementById('services').value.trim()
});
window.addEventListener('message', event => {
  const message = event.data;
  if (message.command === 'applications') document.getElementById('applications').textContent = message.value;
  if (message.command === 'plan') document.getElementById('output').textContent = message.value;
  if (message.command === 'error') {
    document.getElementById('output').textContent = message.value;
    document.getElementById('output').className = 'error';
  }
});
</script>
</body>
</html>`;
}

function runCore(binary: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(binary, args, {
      encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024, windowsHide: true,
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(safeText(stderr.trim() || error.message).slice(0, 300)));
        return;
      }
      resolve(stdout);
    });
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function safeText(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 100000);
}

function errorText(error: unknown): string {
  return error instanceof Error ? safeText(error.message).slice(0, 300) : 'Unknown error';
}
