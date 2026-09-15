import test from 'node:test';
import assert from 'node:assert/strict';
import { configuredSkill, expandArgument, runConfiguredSkill } from '../scripts/lib/skill-execution.mjs';

test('expands only supported skill context placeholders', () => {
  assert.equal(expandArgument('--prompt={prompt}', { prompt: 'hello' }), '--prompt=hello');
  assert.throws(() => expandArgument('{unknown}'), /unsupported/);
});

test('rejects disabled and unconfigured skill execution', () => {
  assert.throws(() => configuredSkill({ policies: { skillExecution: { enabled: false, commands: {} } } }, 'grill-me'), /disabled/);
  assert.throws(() => configuredSkill({ policies: { skillExecution: { enabled: true, commands: {} } } }, 'grill-me'), /no command configured/);
});

test('runs a configured command with separate expanded arguments', async () => {
  const result = await runConfiguredSkill({
    root: process.cwd(),
    config: { policies: { skillExecution: { enabled: true, commands: { demo: { command: process.execPath, args: ['-e', 'process.stdout.write(process.argv[1])', '{prompt}'] } } } } },
    skill: 'demo',
    context: { prompt: 'safe value; not a shell command' }
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, 'safe value; not a shell command');
});
