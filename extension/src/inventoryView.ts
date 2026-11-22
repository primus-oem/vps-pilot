import { execFile } from 'node:child_process';
import * as vscode from 'vscode';

interface ApplicationSummary {
  id: string;
  name: string;
  digest: string;
}

interface ApplicationInventory {
  id: string;
  name: string;
  digest: string;
  environments: Array<{
    name: string;
    protected: boolean;
    hosts: string[];
  }>;
  services: Array<{
    name: string;
    role?: string;
    repository?: string;
    hosts: string[];
    compose_project: string;
    compose_service: string;
    dependencies: string[];
    secret_bindings: Array<{
      name: string;
      source: string;
      status: string;
    }>;
  }>;
}

interface InventoryNode {
  label: string;
  description?: string;
  tooltip?: string;
  children?: InventoryNode[];
  loadChildren?: () => Promise<InventoryNode[]>;
}

export class InventoryTreeProvider implements vscode.TreeDataProvider<InventoryNode> {
  private readonly changes = new vscode.EventEmitter<InventoryNode | undefined>();
  readonly onDidChangeTreeData = this.changes.event;

  constructor(private readonly binaryPath: () => string) {}

  refresh(): void {
    this.changes.fire(undefined);
  }

  dispose(): void {
    this.changes.dispose();
  }

  getTreeItem(node: InventoryNode): vscode.TreeItem {
    const expandable = Boolean(node.loadChildren || (node.children && node.children.length > 0));
    const item = new vscode.TreeItem(
      node.label,
      expandable ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None,
    );
    item.description = node.description;
    item.tooltip = node.tooltip;
    return item;
  }

  async getChildren(node?: InventoryNode): Promise<InventoryNode[]> {
    if (node?.loadChildren) {
      try {
        return await node.loadChildren();
      } catch (error) {
        return [errorNode(error)];
      }
    }
    if (node?.children) {
      return node.children;
    }
    if (node) {
      return [];
    }
    try {
      return await this.loadRoots();
    } catch (error) {
      return [errorNode(error)];
    }
  }

  private async loadRoots(): Promise<InventoryNode[]> {
    const [applicationsOutput, hostsOutput] = await Promise.all([
      runCli(this.binaryPath(), ['app', 'list']),
      runCli(this.binaryPath(), ['host', 'list']),
    ]);
    const applications = parseApplications(applicationsOutput);
    const hosts = parseHosts(hostsOutput);
    return [
      {
        label: 'SSH Hosts',
        description: String(hosts.length),
        children: hosts.map((host) => ({
          label: host.alias,
          description: `${host.environment} · ${host.endpoint}`,
          tooltip: 'SSH identity and private-key paths are not displayed.',
        })),
      },
      {
        label: 'Applications',
        description: String(applications.length),
        children: applications.map((application) => ({
          label: safeLabel(application.name),
          description: application.digest.slice(0, 19),
          loadChildren: async () => applicationNodes(
            await loadApplicationInventory(this.binaryPath(), application.id),
          ),
        })),
      },
    ];
  }
}

interface HostSummary {
  alias: string;
  environment: string;
  endpoint: string;
}

function parseApplications(output: string): ApplicationSummary[] {
  const rows = output.split(/\r?\n/).filter(Boolean);
  return rows.map((row) => {
    const [id, digest, ...rest] = row.split('\t');
    if (!id || !digest || rest.length > 0) {
      throw new Error('The core returned an invalid application list.');
    }
    return { id, name: id, digest };
  });
}

function parseHosts(output: string): HostSummary[] {
  const rows = output.split(/\r?\n/).filter(Boolean);
  return rows.map((row) => {
    const [alias, environment, endpoint, ...rest] = row.split('\t');
    if (!alias || !environment || !endpoint || rest.length > 0) {
      throw new Error('The core returned an invalid host list.');
    }
    return {
      alias: safeLabel(alias),
      environment: safeLabel(environment),
      endpoint: safeLabel(endpoint),
    };
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function parseInventory(value: unknown): ApplicationInventory {
  if (!isRecord(value)
    || typeof value.id !== 'string'
    || typeof value.name !== 'string'
    || typeof value.digest !== 'string'
    || !Array.isArray(value.environments)
    || !Array.isArray(value.services)) {
    throw new Error('The core returned an invalid application inventory.');
  }

  const environments = value.environments.map((environment): ApplicationInventory['environments'][number] => {
    if (!isRecord(environment)
      || typeof environment.name !== 'string'
      || typeof environment.protected !== 'boolean'
      || !isStringArray(environment.hosts)) {
      throw new Error('The core returned invalid environment metadata.');
    }
    return { name: environment.name, protected: environment.protected, hosts: environment.hosts };
  });
  const services = value.services.map((service): ApplicationInventory['services'][number] => {
    if (!isRecord(service)
      || typeof service.name !== 'string'
      || typeof service.compose_project !== 'string'
      || typeof service.compose_service !== 'string'
      || !isStringArray(service.hosts)
      || !isStringArray(service.dependencies)
      || !Array.isArray(service.secret_bindings)) {
      throw new Error('The core returned invalid service metadata.');
    }
    const secretBindings = service.secret_bindings.map((binding): ApplicationInventory['services'][number]['secret_bindings'][number] => {
      if (!isRecord(binding)
        || typeof binding.name !== 'string'
        || typeof binding.source !== 'string'
        || typeof binding.status !== 'string') {
        throw new Error('The core returned invalid secret-binding metadata.');
      }
      return { name: binding.name, source: binding.source, status: binding.status };
    });
    if ((service.role !== undefined && typeof service.role !== 'string')
      || (service.repository !== undefined && typeof service.repository !== 'string')) {
      throw new Error('The core returned invalid optional service metadata.');
    }
    return {
      name: service.name,
      role: service.role,
      repository: service.repository,
      hosts: service.hosts,
      compose_project: service.compose_project,
      compose_service: service.compose_service,
      dependencies: service.dependencies,
      secret_bindings: secretBindings,
    };
  });
  return {
    id: value.id,
    name: value.name,
    digest: value.digest,
    environments,
    services,
  };
}

async function loadApplicationInventory(binaryPath: string, id: string): Promise<ApplicationInventory> {
  const output = await runCli(binaryPath, ['app', 'inventory', id]);
  let value: unknown;
  try {
    value = JSON.parse(output);
  } catch {
    throw new Error('The core returned invalid application inventory JSON.');
  }
  return parseInventory(value);
}

function applicationNodes(inventory: ApplicationInventory): InventoryNode[] {
  const environments: InventoryNode[] = inventory.environments.map((environment) => ({
    label: safeLabel(environment.name),
    description: safeLabel(`${environment.protected ? 'protected' : 'unprotected'} · ${environment.hosts.join(', ') || 'no hosts'}`),
  }));
  const services = inventory.services.map((service): InventoryNode => {
    const children: InventoryNode[] = [];
    if (service.repository) {
      children.push({ label: safeLabel(`Repository: ${service.repository}`) });
    }
    if (service.hosts.length > 0) {
      children.push({ label: safeLabel(`Hosts: ${service.hosts.join(', ')}`) });
    }
    if (service.dependencies.length > 0) {
      children.push({ label: safeLabel(`Depends on: ${service.dependencies.join(', ')}`) });
    }
    for (const binding of service.secret_bindings) {
      children.push({
        label: safeLabel(`Secret: ${binding.name}`),
        description: safeLabel(`${binding.source} · ${binding.status === 'configured_unverified' ? 'configured; presence not verified' : 'status unavailable'}`),
        tooltip: 'Secret values and reference locations are not displayed.',
      });
    }
    return {
      label: safeLabel(service.name),
      description: safeLabel(`${service.role || 'service'} · ${service.compose_project}/${service.compose_service}`),
      children,
    };
  });
  return [
    { label: 'Environments', children: environments },
    { label: 'Services', children: services },
  ];
}

function safeLabel(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 160);
}

function errorNode(error: unknown): InventoryNode {
  const detail = error instanceof Error ? safeLabel(error.message) : 'Unknown inventory error';
  return {
    label: 'Inventory unavailable',
    description: 'Refresh to retry',
    tooltip: detail,
  };
}

function runCli(binaryPath: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(binaryPath, args, {
      encoding: 'utf8',
      timeout: 10000,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    }, (error, stdout, stderr) => {
      if (error) {
        const detail = safeLabel(stderr.trim() || error.message).slice(0, 300);
        reject(new Error(`vps-pilot ${args[0]} ${args[1]} failed: ${detail}`));
        return;
      }
      resolve(stdout);
    });
  });
}
