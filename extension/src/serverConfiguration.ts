import { spawnSync } from 'node:child_process';

export interface ServerConfiguration {
  label: string;
  command: string;
  args: string[];
  version: string;
}

export function validateServerBinary(command: string): string | undefined {
  const result = spawnSync(command, ['version'], {
    encoding: 'utf8',
    timeout: 5000,
    windowsHide: true,
  });
  if (result.error) {
    return result.error.message;
  }
  if (result.status !== 0) {
    return result.stderr.trim() || `exited with status ${result.status ?? 'unknown'}`;
  }
  return undefined;
}

export function createServerConfiguration(binaryPath?: string): ServerConfiguration {
  return {
    label: 'VPS Pilot',
    command: binaryPath?.trim() || 'vps-pilot',
    args: ['mcp'],
    version: '0.1.0',
  };
}