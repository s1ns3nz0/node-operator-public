import { spawn } from 'node:child_process';

const CONTEXT_KEYS = new Set(['prompt', 'artifact', 'evidence']);

export function expandArgument(template, context = {}) {
  return template.replace(/\{([^}]+)\}/g, (match, key) => {
    if (!CONTEXT_KEYS.has(key)) throw new Error(`unsupported skill argument placeholder '${match}'`);
    return context[key] ?? '';
  });
}

export function configuredSkill(config, skill) {
  if (!config.policies?.skillExecution?.enabled) throw new Error('skill execution is disabled; configure commands and set policies.skillExecution.enabled to true');
  const definition = config.policies?.skillExecution?.commands?.[skill];
  if (!definition) throw new Error(`no command configured for skill '${skill}'`);
  return definition;
}

export async function runConfiguredSkill({ root, config, skill, context = {} }) {
  const definition = configuredSkill(config, skill);
  const args = definition.args.map((argument) => expandArgument(argument, context));
  const result = await new Promise((resolve, reject) => {
    const child = spawn(definition.command, args, { cwd: root, shell: false });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (exitCode) => resolve({ exitCode: exitCode ?? 1, stdout, stderr }));
  });
  return { skill, command: definition.command, args, ...result };
}
