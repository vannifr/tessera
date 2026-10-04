// Application Audit Workflow

import {
  defineSignal,
  defineQuery,
  setHandler,
  condition,
  proxyActivities,
  sleep,
  workflowInfo,
  ActivityFailure,
  ApplicationFailure,
  isCancellation,
} from '@temporalio/workflow';
import type * as activities from '../activities';
import type {
  AuditInput,
  AuditResult,
  AuditStatus,
  AuditState,
  Finding,
  TechStack,
  ScopeDocument,
  ComplianceMap,
  ReviewResult,
  ReviewAdvice,
} from '../types';
import type { AuditRun, FetchedSource } from '../scan/lifecycle';
import type { ScanFinding, ScanStepResult } from '../scan/scan-types';
import { computeOutcome } from '../scan/status';
import type { NotPerformed, ScannerId, ScannerStatusEntry } from '../scan/status';

// Import activities
const {
  initAuditRun,
  fetchSource,
  detectTechStack,
  generateScopeDocument,
  runNpmAudit,
  runGitleaks,
  runSemgrep,
  runLicenseCheck,
  reviewCriticalPaths,
  mapToCompliance,
  crossValidate,
  generateReport,
  cleanupRun,
  sealEvidence,
  signEvidence,
} = proxyActivities<typeof activities>({
  startToCloseTimeout: '1 hour',
  retry: {
    initialInterval: '10 seconds',
    maximumInterval: '5 minutes',
    maximumAttempts: 3,
    nonRetryableErrorTypes: ['InvalidRepoError', 'ValidationError', 'InvalidRunError', 'SourceUnavailableError'],
  },
});

// Signals (human-in-the-loop)
export const p0ApprovalSignal = defineSignal<[boolean]>('p0-approval');
export const scopeChangeSignal = defineSignal<[ScopeDocument]>('scope-change');

// Queries (status checks)
export const statusQuery = defineQuery<AuditStatus>('status');
export const findingsQuery = defineQuery<Finding[]>('findings');
export const stateQuery = defineQuery<AuditState>('state');

type ScanActivity = (run: AuditRun, source: FetchedSource, repoUrl: string) => Promise<ScanStepResult>;

interface SettledScan {
  entry: ScannerStatusEntry;
  findings: ScanFinding[];
}

const ALWAYS_REQUIRED: ReadonlySet<ScannerId> = new Set<ScannerId>(['gitleaks', 'semgrep']);

const SCANS: readonly (readonly [ScannerId, ScanActivity])[] = [
  ['gitleaks', runGitleaks],
  ['semgrep', runSemgrep],
  ['npm-audit', runNpmAudit],
  ['license-check', runLicenseCheck],
];

async function awaitP0Approval(state: AuditState, input: AuditInput, evidence: EvidenceSummary): Promise<void> {
  const hasP0 = state.findings.some((f) => f.severity === 'P0');
  if (!hasP0 || input.skipApproval) return;
  state.currentPhase = 'awaiting-approval';
  const approvalTimeout = 7 * 24 * 60 * 60 * 1000;
  const approved = await condition(() => state.p0Approved, approvalTimeout);
  if (!approved) {
    throw ApplicationFailure.create({
      type: 'AuditRejectedError',
      message: 'Audit rejected: P0 findings not approved within timeout',
      nonRetryable: true,
      details: evidenceDetails(evidence),
    });
  }
}

// Workflow definition
export async function applicationAudit(input: AuditInput): Promise<AuditResult> {
  const startTime = new Date();
  const workflowId = workflowInfo().workflowId;

  // Initialize state
  const state: AuditState = {
    currentPhase: 'pending',
    findings: [],
    techStack: null,
    scope: null,
    p0Approved: false,
    scanners: [],
  };

  // Set up signal and query handlers
  setHandler(p0ApprovalSignal, (approved: boolean) => {
    state.p0Approved = approved;
  });

  setHandler(scopeChangeSignal, (newScope: ScopeDocument) => {
    state.scope = newScope;
  });

  setHandler(statusQuery, () => state.currentPhase as AuditStatus);

  setHandler(findingsQuery, () => state.findings);

  setHandler(stateQuery, () => state);

  let run: AuditRun | undefined;
  let cleaned = false;
  let sealed: EvidenceSummary | undefined;
  let sealSource: FetchedSource | null = null;
  let sealAttempted = false;
  let sourceRecordIds: string[] = [];
  let signature: SignatureState | undefined;
  let signatureRequired = false;

  const seal = async (usedRecordIds: string[]): Promise<EvidenceSummary> => {
    if (sealed !== undefined) return sealed;
    if (run === undefined) throw new Error('no audit run to seal');
    sealAttempted = true;
    const result = await sealEvidence({ run, source: sealSource, repoUrl: input.repoUrl, usedRecordIds: unique(usedRecordIds), workflowId });
    if (result?.selfVerified !== true) {
      throw ApplicationFailure.create({ type: 'EvidenceSealError', message: 'Evidence bundle failed its self-verification', nonRetryable: true });
    }
    sealed = { bundlePath: result.bundlePath, rootHash: result.rootHash, recordCount: result.recordCount };
    signatureRequired = result.signatureRequired === true;
    return sealed;
  };

  const sign = async (evidence: EvidenceSummary): Promise<SignatureState> => {
    if (signature !== undefined) return signature;
    if (run === undefined) throw new Error('no audit run to sign');
    try {
      const state = signatureState(await signEvidence({ run, rootHash: evidence.rootHash }));
      signature = { ...state, required: state.required || signatureRequired };
    } catch (error) {
      if (isCancellation(error)) throw error;
      signature = { signed: false, required: signatureRequired, level: 0, detail: `signing activity failed (${failureType(error)})` };
    }
    return signature;
  };

  const sealBestEffort = async (usedRecordIds: string[]): Promise<EvidenceSummary | undefined> => {
    let evidence: EvidenceSummary;
    try {
      evidence = await seal(usedRecordIds);
    } catch {
      return undefined;
    }
    await sign(evidence);
    return evidence;
  };

  const removeWorkDir = async (): Promise<void> => {
    if (run === undefined || cleaned) return;
    cleaned = true;
    await cleanupRun(run);
  };

  try {
    state.currentPhase = 'discovery';

    run = await initAuditRun();

    let source: FetchedSource;
    try {
      source = await fetchSource(run, input.repoUrl);
    } catch (error) {
      if (isCancellation(error)) throw error;
      const evidence = await sealBestEffort(sourceEvidenceIds(error));
      const failure = sourceFailure(error, evidence);
      state.outcome = 'incomplete';
      state.notPerformed = (failure.details?.[0] as { notPerformed: NotPerformed[] }).notPerformed;
      throw failure;
    }
    state.revision = source.revision;
    sealSource = source;
    sourceRecordIds = stringList(source.evidenceRecordIds);
    const repoPath = source.repoDir;

    // Detect tech stack
    state.techStack = await detectTechStack(repoPath);

    // Generate scope document
    state.scope = await generateScopeDocument(
      state.techStack,
      input.frameworks || ['OWASP-ASVS'],
      input.scope || 'full'
    );

    // Guardrail: Input validation
    if (!state.techStack || state.techStack.language === 'unknown') {
      const evidence = await sealBestEffort(sourceRecordIds);
      throw ApplicationFailure.create({
        type: 'TechStackNotDetectedError',
        message: 'Could not detect tech stack - aborting audit',
        nonRetryable: true,
        details: evidenceDetails(evidence),
      });
    }

    // ==================== FASE 1: AUTOMATED SCANS ====================
    state.currentPhase = 'scanning';

    const activeRun = run;
    const settled = await Promise.all(
      SCANS.map(([scanner, scan]) => settle(scanner, scan(activeRun, source, input.repoUrl)))
    );
    const scanFindings = settled.flatMap((s) => s.findings);
    state.findings = [...scanFindings];

    // ==================== FASE 2: CODE REVIEW ====================
    state.currentPhase = 'reviewing';

    // Identify critical paths based on tech stack
    const criticalPaths = identifyCriticalPaths(state.techStack);

    const review = await settleReview(reviewCriticalPaths(repoPath, criticalPaths, 'OWASP-Top-10'));

    await removeWorkDir();

    const scanners = [...settled.map((s) => s.entry), review.entry];
    const recordIds = new Set(scanners.flatMap((s) => s.evidenceRecordIds));
    const baseDecisionInput = {
      scanners,
      untracedFindingIds: scanFindings.filter((f) => !traced(f, recordIds)).map((f) => f.id),
    };
    const baseDecision = computeOutcome(baseDecisionInput);
    state.scanners = scanners;
    state.outcome = baseDecision.outcome;
    state.notPerformed = baseDecision.notPerformed;
    state.findings = [...scanFindings, ...review.findings];

    const evidence = await seal([
      ...sourceRecordIds,
      ...scanners.flatMap((s) => s.evidenceRecordIds),
      ...state.findings.map((f) => f as ScanFinding).filter((f) => traced(f, recordIds)).map((f) => f.evidenceRef?.recordId ?? ''),
    ]);
    const signed = await sign(evidence);
    const decision = computeOutcome({
      scanners,
      untracedFindingIds: baseDecisionInput.untracedFindingIds,
      evidenceSignature: { required: signed.required, level: signed.level, ...(signed.detail === undefined ? {} : { detail: signed.detail }) },
    });
    state.outcome = decision.outcome;
    state.notPerformed = decision.notPerformed;
    const signatureSummary = publicSignature(signed);

    // ==================== FASE 3: COMPLIANCE MAPPING ====================
    state.currentPhase = 'compliance';

    // Map findings to compliance frameworks
    const complianceMaps = await mapToCompliance(
      state.findings,
      state.scope.frameworks
    );

    // ==================== FASE 4: CROSS-VALIDATION ====================
    state.currentPhase = 'validation';

    // Review by different model (Qwen3-max)
    const reviewResult = await crossValidate({
      findings: state.findings,
      complianceMaps,
      model: 'qwen3-max',
    });

    const reviewAdvice = reviewAdviceFor(state.findings, reviewResult);
    state.reviewAdvice = reviewAdvice;

    // ==================== FASE 5: HUMAN APPROVAL ====================

    await awaitP0Approval(state, input, evidence);

    // ==================== FASE 6: REPORT GENERATION ====================
    state.currentPhase = 'reporting';

    // Generate report
    const report = await generateReport({
      repoUrl: input.repoUrl,
      workflowId,
      techStack: state.techStack,
      scope: state.scope,
      findings: state.findings,
      complianceMaps,
      reviewResult,
      outputDir: input.outputDir,
      outcome: decision.outcome,
      notPerformed: decision.notPerformed,
      scanners,
      revision: source.revision,
      evidence: { bundlePath: evidence.bundlePath, rootHash: evidence.rootHash },
      signature: signatureSummary,
      ...(source.overrideAttempts === undefined ? {} : { overrideAttempts: source.overrideAttempts }),
    });

    state.currentPhase = 'completed';
    const endTime = new Date();

    return {
      status: 'completed',
      findings: state.findings,
      complianceMap: complianceMaps,
      reportPath: report.reportPath,
      evidencePath: report.evidencePath,
      duration: endTime.getTime() - startTime.getTime(),
      startTime,
      endTime,
      outcome: decision.outcome,
      notPerformed: decision.notPerformed,
      scanners,
      source: { repoUrl: input.repoUrl, revision: source.revision },
      reviewAdvice,
      evidence,
      signature: signatureSummary,
    };
  } catch (error) {
    state.currentPhase = 'failed';
    state.error = error instanceof Error ? error.message : String(error);
    if (run !== undefined && !sealAttempted && !isCancellation(error)) await sealBestEffort(sourceRecordIds);

    throw error;
  } finally {
    await removeWorkDir().catch(() => undefined);
  }
}

function failureType(error: unknown): string {
  const cause = error instanceof ActivityFailure ? error.cause : error;
  return cause instanceof ApplicationFailure && typeof cause.type === 'string' ? cause.type : 'unknown';
}

interface EvidenceSummary {
  bundlePath: string;
  rootHash: string;
  recordCount: number;
}

interface SignatureState {
  signed: boolean;
  required: boolean;
  keyId?: string;
  signedAt?: string;
  level: 0 | 1;
  detail?: string;
}

function signatureState(result: unknown): SignatureState {
  const r = (typeof result === 'object' && result !== null ? result : {}) as Record<string, unknown>;
  const required = r.required === true;
  const signed = r.signed === true;
  const keyId = typeof r.keyId === 'string' && /^[0-9a-f]{64}$/.test(r.keyId) ? r.keyId : undefined;
  const signedAt = typeof r.signedAt === 'string' ? r.signedAt : undefined;
  const level: 0 | 1 = r.level === 1 && signed && keyId !== undefined ? 1 : 0;
  const state: SignatureState = { signed, required, level };
  if (keyId !== undefined) state.keyId = keyId;
  if (signedAt !== undefined) state.signedAt = signedAt;
  if (typeof r.detail === 'string') state.detail = r.detail;
  else if (r.level === 1 && level === 0) state.detail = 'signing activity returned an inconsistent result';
  return state;
}

function publicSignature(s: SignatureState): NonNullable<AuditResult['signature']> {
  const out: NonNullable<AuditResult['signature']> = { signed: s.signed, level: s.level };
  if (s.keyId !== undefined) out.keyId = s.keyId;
  if (s.signedAt !== undefined) out.signedAt = s.signedAt;
  return out;
}

function unique(ids: string[]): string[] {
  return [...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0))];
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function sourceEvidenceIds(error: unknown): string[] {
  const cause = error instanceof ActivityFailure ? error.cause : error;
  if (!(cause instanceof ApplicationFailure)) return [];
  const detail = cause.details?.[0] as { evidenceRecordIds?: unknown } | undefined;
  return stringList(detail?.evidenceRecordIds);
}

function evidenceDetails(evidence: EvidenceSummary | undefined): unknown[] {
  return evidence === undefined ? [] : [{ evidence: { bundlePath: evidence.bundlePath, rootHash: evidence.rootHash } }];
}

function sourceFailure(error: unknown, evidence: EvidenceSummary | undefined): ApplicationFailure {
  const network = failureType(error) === 'SourceNetworkError';
  const notPerformed: NotPerformed = {
    scanner: 'source',
    status: 'failed',
    cause: network ? 'network' : 'source-unavailable',
    summary: network
      ? 'The source could not be fetched because of a network problem; no scanner ran.'
      : 'The source could not be retrieved; no scanner ran.',
  };
  return ApplicationFailure.create({
    type: network ? 'SourceNetworkError' : 'SourceUnavailableError',
    message: `Audit not performed: ${notPerformed.summary}`,
    nonRetryable: !network,
    details: [
      {
        outcome: 'incomplete',
        notPerformed: [notPerformed],
        ...(evidence === undefined ? {} : { evidence: { bundlePath: evidence.bundlePath, rootHash: evidence.rootHash } }),
      },
    ],
    cause: error instanceof Error ? error : undefined,
  });
}

function failedEntry(scanner: ScannerId, required: boolean, heuristic: boolean, detail: string): ScannerStatusEntry {
  return {
    scanner,
    required,
    status: 'failed',
    cause: 'activity-failed',
    causeDetail: detail,
    heuristic,
    toolVersion: null,
    findingCount: 0,
    evidenceRecordIds: [],
  };
}

async function settle(scanner: ScannerId, pending: Promise<ScanStepResult>): Promise<SettledScan> {
  let result: ScanStepResult;
  try {
    result = await pending;
  } catch (error) {
    if (isCancellation(error)) throw error;
    return { entry: failedEntry(scanner, true, false, `activity failed (${failureType(error)})`), findings: [] };
  }
  if (result?.scanner !== scanner || result.status?.scanner !== scanner) {
    return { entry: failedEntry(scanner, true, false, 'activity returned a result for another scanner'), findings: [] };
  }
  const notApplicable = result.status.status === 'skipped' && result.status.cause === 'not-applicable';
  const entry: ScannerStatusEntry = {
    ...result.status,
    required: result.status.required || ALWAYS_REQUIRED.has(scanner) || !notApplicable,
    heuristic: false,
  };
  return { entry, findings: result.findings };
}

async function settleReview(pending: Promise<Finding[]>): Promise<SettledScan> {
  let found: Finding[];
  try {
    found = await pending;
  } catch (error) {
    if (isCancellation(error)) throw error;
    return { entry: failedEntry('code-review', false, true, `activity failed (${failureType(error)})`), findings: [] };
  }
  const findings: ScanFinding[] = found.map((f) => ({ ...f, scanner: 'code-review', heuristic: true }));
  return {
    entry: {
      scanner: 'code-review',
      required: false,
      heuristic: true,
      status: 'completed',
      toolVersion: null,
      findingCount: findings.length,
      evidenceRecordIds: [],
    },
    findings,
  };
}

function traced(finding: ScanFinding, recordIds: ReadonlySet<string>): boolean {
  const ref = finding.evidenceRef;
  return ref !== undefined && typeof ref.recordId === 'string' && recordIds.has(ref.recordId);
}

// Helper functions
function identifyCriticalPaths(techStack: TechStack): string[] {
  const paths = ['auth', 'login', 'password', 'session', 'token'];

  if (techStack.hasPayments) {
    paths.push('payment', 'checkout', 'card', 'stripe');
  }

  if (techStack.hasPII) {
    paths.push('user', 'profile', 'email', 'address');
  }

  if (techStack.database) {
    paths.push('database', 'query', 'sql', 'model');
  }

  return paths;
}

function reviewAdviceFor(findings: Finding[], review: ReviewResult): ReviewAdvice[] {
  const advice: ReviewAdvice[] = [];
  for (const correction of review.severityCorrections ?? []) {
    const finding = findings.find(f => f.id === correction.findingId);
    if (finding === undefined) continue;
    advice.push({
      findingId: finding.id,
      kind: 'severity-correction',
      currentSeverity: finding.severity,
      suggestedSeverity: correction.newSeverity,
      reason: correction.reason,
    });
  }
  for (const id of review.falsePositives ?? []) {
    if (findings.some(f => f.id === id)) advice.push({ findingId: id, kind: 'false-positive' });
  }
  return advice;
}