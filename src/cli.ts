#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const USAGE = `hardening - versioned control catalogue, verification checks, and release evidence

Usage:
  hardening <command> [options]

Commands:
  help      Show this message
  version   Print the tool version

Commands not yet implemented (later steps):
  validate  Check schemas, profiles, IDs, mappings, exceptions, and record freshness
  plan      Derive the expected check list before anything runs
  check     Run applicable checks and normalize outputs
  gate      Evaluate the gate and return a decision with reason codes
  report    Produce JSON and Markdown from the same evaluation as gate
`;

function fail(message: string): never {
  process.stderr.write(`hardening: ${message}\n`);
  process.exit(2);
}

function readVersion(): string {
  const manifest: unknown = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
  );
  const version = (manifest as { version?: unknown }).version;
  if (typeof version !== 'string') fail('package.json has no version field');
  return version;
}

const { positionals } = parseArgs({
  args: process.argv.slice(2),
  allowPositionals: true,
  options: {},
  strict: true,
});

const command = positionals[0] ?? 'help';

switch (command) {
  case 'help':
    process.stdout.write(USAGE);
    process.exit(0);
    break;
  case 'version':
    process.stdout.write(`${readVersion()}\n`);
    process.exit(0);
    break;
  default:
    fail(`unknown command '${command}'. Run \`hardening help\`.`);
}
