import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServerConfiguration, validateServerBinary } from '../src/serverConfiguration';

test('uses the default executable and starts MCP over stdio', () => {
  assert.deepEqual(createServerConfiguration(), {
      label: 'VPS Pilot',
      command: 'vps-pilot',
      args: ['mcp'],
      version: '0.1.0',
  });
});

test('uses a trimmed configured executable path', () => {
  assert.equal(createServerConfiguration('  /opt/vps-pilot  ').command, '/opt/vps-pilot');
});

test('reports an unavailable executable', () => {
  assert.ok(validateServerBinary('/definitely/missing/vps-pilot'));
});