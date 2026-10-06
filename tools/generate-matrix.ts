#!/usr/bin/env node
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateMatrix } from '../dist/domain/matrix.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const result = generateMatrix({
  matrixPath: join(root, 'controls', 'matrix.md'),
  reviewSheetPath: join(root, 'docs', 'checkpoints', 'control-review-sheet.md'),
});

process.stdout.write(`generated ${result.matrixPath}\ngenerated ${result.reviewSheetPath}\n`);
