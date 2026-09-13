#!/usr/bin/env node
// Thin entry point; all logic lives in src/cli.ts.
import { main } from '../src/cli.ts';

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e) => {
    process.stderr.write(`lexsieve: ${(e && e.message) || 'internal error'}\n`);
    process.exitCode = 4;
  });
