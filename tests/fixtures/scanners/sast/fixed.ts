// FIXTURE: safe equivalents of the vulnerable patterns. Never executed.
import { readdir } from 'node:fs/promises';

export function parse(value: string): unknown {
  return JSON.parse(value);
}

export function listDirectory(directory: string): Promise<string[]> {
  return readdir(directory);
}

export function render(element: { textContent: string }, userInput: string): void {
  element.textContent = userInput;
}
