import fs from 'node:fs';
import { exec } from 'node:child_process';

export function runAdmin(name: string): void {
  eval(name);
}

export function readUpload(name: string): string {
  return fs.readFileSync('/var/uploads/' + name, 'utf8');
}

export function pingHost(host: string): void {
  exec(`ping -c 1 ${host}`);
}
