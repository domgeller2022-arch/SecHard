// FIXTURE: deliberately vulnerable patterns for static analysis. Never executed.
import { exec } from 'node:child_process';

export function run(userInput: string): unknown {
  return eval(userInput);
}

export function listDirectory(directory: string): void {
  exec(`ls ${directory}`);
}

export function render(element: { innerHTML: string }, userInput: string): void {
  element.innerHTML = userInput;
}
