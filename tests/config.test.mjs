import test from 'node:test';
import assert from 'node:assert/strict';
import { validateConfig } from '../scripts/lib/config.mjs';

const valid = {
  schemaVersion: 1, project: { name: 'demo', description: '' }, paperthin: { source: 'github:a/b', ref: 'abc123' },
  models: { tiers: { sol: { model: 'sol' }, terra: { model: 'terra' }, luna: { model: 'luna' } }, fallback: 'nearest', recordFallbacks: true },
  policies: { externalActions: 'explicit', worktreesRequiredForMutations: true, humanApprovalForPromotedLearnings: true, ambiguityResolution: { enabled: true, thinAskResolver: 'paperthin:aim', intentChecker: 'paperthin:readchk', riskCarver: 'paperthin:autobahn', interviewer: 'grill-me', consolidator: 'paperthin:ssotize', decisionChallenge: 'paperthin:feynman', adversarialPlanCheck: 'paperthin:hate', hateCheckpoints: ['after-non-trivial-plan', 'before-irreversible-or-high-cost-stage'], requiresExplicitUserAcceptance: true, safeCorrectionAttemptsBeforeInterview: 1, blockAffectedNodeWhenUnresolved: true, decisionRecordsDirectory: 'docs/decisions', productSpecsDirectory: 'docs/product-specs' }, admissibility: { enabled: true, orchestrator: 'paperthin:sip', runAfterDurableArtifactChange: true, unexplainable: { check: 'paperthin:shower', blocksCompletion: true }, unreasonable: { checks: ['paperthin:factchk', 'paperthin:mandela'], blocksWhen: 'falsified-requirement-claim-or-evaluation' }, unacceptable: { check: 'paperthin:autobahn', blocksCompletion: true, continueSafeRemainder: true }, safeCorrectionAttemptsBeforeEscalation: 1, recordSkippedChecks: true }, roleQuality: { luna: { requiredEvidence: ['task findings'], conditionalSkills: ['paperthin:factchk', 'paperthin:mandela'] }, terra: { requiredSkills: ['paperthin:sip'], requiredEvidence: ['checks'] }, sol: { requiredSkills: ['paperthin:shower'], controlledSkills: ['paperthin:autobahn', 'grill-me', 'paperthin:hate'], requiredEvidence: ['integration'] } }, knowledgeSteward: { enabled: true, invocation: 'explicit-user', defaultTier: 'terra', readOnly: true, defaultPersistence: 'chat-only', canonicalWikiDirectory: 'docs', reentrySkill: 'paperthin:catchup', driftAudit: 'paperthin:ssotize', auditTriggers: ['accepted-product-spec-change', 'accepted-decision-change', 'explicit-request'] }, requirementsSteward: { enabled: true, invocation: 'explicit-user', defaultTier: 'terra', canonicalDirectory: 'docs/product-specs', usesProcess: 'write-a-prd-adapted', opensGitHubIssue: false, requiresExplicitApproval: true, taskRequiresApprovedProductSpec: true }, solidReview: { enabled: true, appliesTo: 'oo', defaultTier: 'terra', preImplementationRequired: true, integrationRerunTriggers: ['interface'], reportFile: 'solid-review.md', blocksMaterialFindings: true } },
  adapters: { active: [], definitions: {} }
};
valid.policies.workflowRouting = { defaultMode: 'lightweight', fullWorkflowTriggers: ['product-design'], lightweight: { maxToolCalls: 3, maxValidationCommands: 1, delegation: 'forbidden', durableArtifacts: false } };
valid.policies.testPortability = { requiredPlatform: 'linux', vendorNeutral: true, allowLocalOnlyRequired: false };
valid.policies.promptIntake = { enabled: true, handler: 'grill-me', when: 'full-workflow', mode: 'one-question-at-a-time', blocksWorkUntilComplete: true };
valid.policies.skillExecution = { enabled: false, commands: {}, requiredSkills: ['grill-me', 'sip', 'shower'], conditionalSkills: ['factchk'] };
valid.policies.admissibility.requiredWhen = 'full-workflow';
valid.policies.showDontTell = { enabled: true, requiredForObservableBehavior: true, independentReview: true, commitSmallArtifacts: true, userAcceptanceBlocksOnlyWhenConfigured: true, reportFile: 'demonstration.md' };
test('accepts a complete configuration', () => assert.deepEqual(validateConfig(valid), []));
test('reports missing tier and selected adapter', () => {
  const broken = structuredClone(valid); delete broken.models.tiers.luna; broken.adapters.active = ['missing'];
  assert.match(validateConfig(broken).join('\n'), /luna.*model/);
  assert.match(validateConfig(broken).join('\n'), /missing.*no definition/);
});

test('requires a complete ambiguity-resolution policy', () => {
  const broken = structuredClone(valid); delete broken.policies.ambiguityResolution.interviewer;
  assert.match(validateConfig(broken).join('\n'), /ambiguityResolution\.interviewer/);
});

test('requires a complete admissibility policy', () => {
  const broken = structuredClone(valid); delete broken.policies.admissibility.orchestrator;
  assert.match(validateConfig(broken).join('\n'), /admissibility\.orchestrator/);
});

test('requires evidence obligations for every role', () => {
  const broken = structuredClone(valid); delete broken.policies.roleQuality.sol.requiredEvidence;
  assert.match(validateConfig(broken).join('\n'), /roleQuality\.sol\.requiredEvidence/);
});

test('requires a complete knowledge-steward policy', () => {
  const broken = structuredClone(valid); delete broken.policies.knowledgeSteward.reentrySkill;
  assert.match(validateConfig(broken).join('\n'), /knowledgeSteward\.reentrySkill/);
});

test('requires a complete requirements-steward policy', () => {
  const broken = structuredClone(valid); delete broken.policies.requirementsSteward.canonicalDirectory;
  assert.match(validateConfig(broken).join('\n'), /requirementsSteward\.canonicalDirectory/);
});

test('requires a complete solid-review policy', () => {
  const broken = structuredClone(valid); delete broken.policies.solidReview;
  assert.match(validateConfig(broken).join('\n'), /policies\.solidReview/);
});
