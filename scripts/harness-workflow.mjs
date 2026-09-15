#!/usr/bin/env node
import { appendFile } from 'node:fs/promises';
import { readConfig } from './lib/config.mjs';
import { runConfiguredSkill } from './lib/skill-execution.mjs';

const args = process.argv.slice(2);
const option = (name) => args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
const values = (name) => args.flatMap((value, index) => value === name && args[index + 1] ? [args[index + 1]] : []);
const stage = option('--stage');
const stageSkills = { 'prompt-intake': ['grill-me'], 'artifact-review': ['sip', 'shower'] };
if (args.includes('--help') || !stageSkills[stage]) {
  console.log('Usage: npm run harness:workflow -- --stage <prompt-intake|artifact-review> [--prompt <text>] [--artifact <path>] [--evidence <path>] [--condition <skill>] [--record <jsonl-file>]');
  process.exit(args.includes('--help') ? 0 : 1);
}

try {
  const root = process.cwd();
  const config = await readConfig(root);
  const context = { prompt: option('--prompt'), artifact: option('--artifact'), evidence: option('--evidence') };
  const skills = [...stageSkills[stage], ...values('--condition')];
  const conditional = new Set(config.policies.skillExecution.conditionalSkills);
  const records = [];
  for (const skill of skills) {
    try {
      const result = await runConfiguredSkill({ root, config, skill, context });
      records.push({ ...result, stage, timestamp: new Date().toISOString() });
      if (result.stdout) process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
      if (result.exitCode !== 0) process.exit(result.exitCode);
    } catch (error) {
      if (!conditional.has(skill)) throw error;
      records.push({ skill, stage, skipped: true, reason: error.message, timestamp: new Date().toISOString() });
    }
  }
  if (option('--record')) await appendFile(option('--record'), `${records.map(JSON.stringify).join('\n')}\n`, 'utf8');
} catch (error) {
  console.error(`FAIL ${error.message}`);
  process.exit(1);
}
