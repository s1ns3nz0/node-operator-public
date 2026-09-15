import { mkdir, writeFile, access, readFile } from 'node:fs/promises';
import path from 'node:path';
const root = process.cwd();
for (const directory of ['plans', 'reports', 'docs/decisions', 'docs/product-specs']) await mkdir(path.join(root, directory), { recursive: true });
for (const file of ['plans/README.md', 'reports/.gitkeep']) try { await access(path.join(root, file)); } catch { await writeFile(path.join(root, file), file.endsWith('.md') ? '# Execution plans\n\nNon-trivial work has a task graph and evidence bundle.\n' : ''); }
const configFile = path.join(root, 'harness.config.json');
try {
  const config = JSON.parse(await readFile(configFile, 'utf8'));
  if (config.project?.name === 'replace-with-project-name') {
    const args = process.argv.slice(2);
    const value = (flag) => { const index = args.indexOf(flag); return index >= 0 ? args[index + 1] : undefined; };
    config.project.name = value('--name') || path.basename(root);
    config.project.description = value('--description') || config.project.description || `Project ${config.project.name} using the Codex harness.`;
    await writeFile(configFile, `${JSON.stringify(config, null, 2)}\n`);
  }
} catch { /* Initialization remains non-destructive when no config exists. */ }
console.log('PASS harness directories initialized without overwriting repository values.');
