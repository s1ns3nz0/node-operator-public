import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('initializer fills template project identity without overwriting existing values', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'codex-harness-'));
  try {
    await writeFile(path.join(directory, 'package.json'), '{}\n');
    const template = JSON.parse(await readFile(path.join(root, 'harness.config.json')));
    template.project = { name: 'replace-with-project-name', description: 'A project using the reusable Codex harness' };
    await writeFile(path.join(directory, 'harness.config.json'), `${JSON.stringify(template)}\n`);
    let result = spawnSync(process.execPath, [path.join(root, 'scripts/harness-init.mjs'), '--name', 'example', '--description', 'Example project'], { cwd: directory, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    let config = JSON.parse(await readFile(path.join(directory, 'harness.config.json')));
    assert.equal(config.project.name, 'example');
    config.project.name = 'keep-me';
    await writeFile(path.join(directory, 'harness.config.json'), `${JSON.stringify(config)}\n`);
    result = spawnSync(process.execPath, [path.join(root, 'scripts/harness-init.mjs'), '--name', 'other'], { cwd: directory, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    config = JSON.parse(await readFile(path.join(directory, 'harness.config.json')));
    assert.equal(config.project.name, 'keep-me');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
