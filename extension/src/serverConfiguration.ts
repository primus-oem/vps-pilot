export interface ServerConfiguration {
  label: string;
  command: string;
  args: string[];
  version: string;
}

export function createServerConfiguration(binaryPath?: string): ServerConfiguration {
  return {
    label: 'VPS Pilot',
    command: binaryPath?.trim() || 'vps-pilot',
    args: ['mcp'],
    version: '0.1.0',
  };
}