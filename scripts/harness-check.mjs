import { readdir, readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { readConfig, validateConfig } from './lib/config.mjs';

const root = process.cwd();
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: npm run harness:check -- [--run-adapters] [--adapter <name>]');
  console.log('Default behavior is dry validation: adapter commands are listed but not executed.');
  process.exit(0);
}
const runAdapters = args.includes('--run-adapters');
const selected = args.flatMap((value, index) => value === '--adapter' && args[index + 1] ? [args[index + 1]] : []);
const failures = [];
let config;
try {
  config = await readConfig(root);
  failures.push(...validateConfig(config));
} catch (error) {
  failures.push(error.message);
}
try {
  const lock = JSON.parse(await readFile(path.join(root, 'harness/paperthin.lock'), 'utf8'));
  if (lock.revision !== config?.paperthin?.ref) failures.push('paperthin.ref must match harness/paperthin.lock revision');
} catch (error) {
  failures.push(`cannot read harness/paperthin.lock: ${error.message}`);
}
try {
  const lock = JSON.parse(await readFile(path.join(root, 'harness/grill-me.lock'), 'utf8'));
  if (lock.dependency !== 'grill-me' || typeof lock.repository !== 'string' || typeof lock.revision !== 'string') failures.push('invalid harness/grill-me.lock metadata');
} catch (error) {
  failures.push(`cannot read harness/grill-me.lock: ${error.message}`);
}
for (const file of ['harness/paperthin.lock', 'harness/grill-me.lock']) try { JSON.parse(await readFile(path.join(root, file), 'utf8')); } catch { failures.push(`invalid lock: ${file}`); }
async function graphs(directory) { try { const entries = await readdir(directory, { withFileTypes: true }); return (await Promise.all(entries.map((entry) => entry.isDirectory() ? graphs(path.join(directory, entry.name)) : entry.name === 'graph.json' ? [path.join(directory, entry.name)] : []))).flat(); } catch { return []; } }
const graphFiles = await graphs(path.join(root, config.graphs.directory));
for (const file of graphFiles) { try { const graph = JSON.parse(await readFile(file, 'utf8')); const ids = new Set(graph.nodes?.map((node) => node.id)); if (!graph.task_id || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges) || graph.edges.some((edge) => !ids.has(edge.from) || !ids.has(edge.to))) failures.push(`invalid graph: ${path.relative(root, file)}`); } catch { failures.push(`invalid graph JSON: ${path.relative(root, file)}`); } }
if (failures.length) { failures.forEach((failure) => console.error(`FAIL ${failure}`)); process.exit(1); }
const active = selected.length ? selected : (config.adapters?.active ?? []);
console.log(`PASS harness configuration; checked ${graphFiles.length} task graph(s).`);
if (!runAdapters) {
  console.log(active.length ? `DRY RUN adapters not executed: ${active.join(', ')}. Re-run with --run-adapters.` : 'SKIP adapters: none are active.');
  process.exit(0);
}
if (!active.length) { console.log('SKIP adapters: none are active.'); process.exit(0); }
for (const adapter of active) {
  const commands = config.adapters?.definitions?.[adapter]?.commands;
  if (!commands || typeof commands !== 'object') { failures.push(`adapter '${adapter}' has no commands object`); continue; }
  for (const [name, command] of Object.entries(commands)) {
    console.log(`RUN ${adapter}:${name}: ${command}`);
    const code = await new Promise((resolve) => spawn(command, { cwd: root, shell: true, stdio: 'inherit' }).on('exit', (status) => resolve(status ?? 1)));
    if (code) failures.push(`adapter '${adapter}' command '${name}' exited ${code}`);
  }
}
if (failures.length) { failures.forEach((failure) => console.error(`FAIL ${failure}`)); process.exit(1); }
console.log('PASS adapter commands.');
