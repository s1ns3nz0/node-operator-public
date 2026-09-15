#!/usr/bin/env node
import { appendFile } from 'node:fs/promises';
import { readConfig } from './lib/config.mjs';
import { runConfiguredSkill } from './lib/skill-execution.mjs';

const args = process.argv.slice(2);
const option = (name) => args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
const skill = option('--skill');
if (args.includes('--help') || !skill) {
  console.log('Usage: npm run harness:skill -- --skill <name> [--prompt <text>] [--artifact <path>] [--evidence <path>] [--record <jsonl-file>]');
  process.exit(args.includes('--help') ? 0 : 1);
}

try {
  const result = await runConfiguredSkill({
    root: process.cwd(),
    config: await readConfig(process.cwd()),
    skill,
    context: { prompt: option('--prompt'), artifact: option('--artifact'), evidence: option('--evidence') }
  });
  const record = { ...result, timestamp: new Date().toISOString() };
  if (option('--record')) await appendFile(option('--record'), `${JSON.stringify(record)}\n`, 'utf8');
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.exitCode !== 0) process.exit(result.exitCode);
} catch (error) {
  console.error(`FAIL ${error.message}`);
  process.exit(1);
}
