// Application Audit Activities

import {
  Context,
  ApplicationFailure,
} from '@temporalio/activity';
import logger from '../logger';
import { exec } from 'child_process';
import { promisify } from 'util';
import {
  promises as fs,
  existsSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
} from 'fs';
import * as path from 'path';
import * as os from 'node:os';
import * as lifecycle from '../scan/lifecycle';
import type { AuditRun, FetchedSource } from '../scan/lifecycle';
import { defaultProcessRunner } from '../scan/process-runner';
import { createEvidenceStore } from '../evidence/store';
import { redactSecrets } from '../evidence/redact';
import { renderOutcomeBlock } from '../report/outcome-block';
import type { ReportSignature } from '../report/outcome-block';
import { walkSourceFiles, readSourceFile } from '../scan/safe-walk';
import { sanitizeOverrideAttempts, steeringCounts } from '../scan/source-probe';
import type { OverrideAttempt } from '../evidence/types';
import { createScanActivities } from '../scan/activities';
import type { ScanActivities, ScanActivity, SealEvidenceActivityInput, SealEvidenceActivityResult, SignEvidenceActivityInput, SignEvidenceResult } from '../scan/activities';
import type { AuditOutcome, NotPerformed, ScannerStatusEntry } from '../scan/status';
import type {
  Finding,
  TechStack,
  ScopeDocument,
  ComplianceMap,
  ReviewResult,
  Evidence,
  Remediation,
  ComplianceFramework,
} from '../types';

const execAsync = promisify(exec);

// ==================== TOOL REQUIREMENTS ACTIVITY ====================

export interface ToolStatus {
  name: string;
  installed: boolean;
  version?: string;
  required: boolean;
  installCommand?: string;
}

const TOOL_REQUIREMENTS: Record<string, { required: boolean; installCommand: string }> = {
  npm: { required: true, installCommand: 'Install Node.js from https://nodejs.org' },
  git: { required: true, installCommand: 'Install from https://git-scm.com' },
  gitleaks: { required: false, installCommand: 'go install github.com/gitleaks/gitleaks/v8@latest' },
  semgrep: { required: false, installCommand: 'pip install semgrep OR brew install semgrep' },
};

/**
 * Check which audit tools are installed and available
 * Should be called at the start of an audit workflow
 */
export async function checkToolRequirements(): Promise<ToolStatus[]> {
  const results: ToolStatus[] = [];

  for (const [tool, config] of Object.entries(TOOL_REQUIREMENTS)) {
    try {
      const { stdout } = await execAsync(`${tool} --version`, { timeout: 5000 });
      const version = stdout.trim().split('\n')[0];
      results.push({
        name: tool,
        installed: true,
        version,
        required: config.required,
      });
      logger.info({ tool, version }, 'Tool available');
    } catch {
      results.push({
        name: tool,
        installed: false,
        required: config.required,
        installCommand: config.installCommand,
      });
      logger.warn({ tool, required: config.required }, 'Tool not found');
    }
  }

  return results;
}

/**
 * Get list of missing required tools
 */
export function getMissingRequiredTools(status: ToolStatus[]): ToolStatus[] {
  return status.filter(t => !t.installed && t.required);
}

/**
 * Get list of missing optional tools
 */
export function getMissingOptionalTools(status: ToolStatus[]): ToolStatus[] {
  return status.filter(t => !t.installed && !t.required);
}

// ==================== REPOSITORY ACTIVITIES ====================

export { validateRepoUrl } from '../scan/repo-url';

// ==================== DISCOVERY ACTIVITIES ====================

export async function detectTechStack(repoPath: string): Promise<TechStack> {
  const techStack: TechStack = {
    language: 'unknown',
    frameworks: [],
    hasPayments: false,
    hasPII: false,
    packageManager: 'npm',
  };

  try {
    // Check for package.json (Node.js)
    const packageJsonPath = path.join(repoPath, 'package.json');
    if (existsSync(packageJsonPath)) {
      techStack.language = 'nodejs';
      const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

      // Detect frameworks
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps.next) techStack.frameworks.push('Next.js');
      if (deps.react) techStack.frameworks.push('React');
      if (deps.vue) techStack.frameworks.push('Vue');
      if (deps.express) techStack.frameworks.push('Express');
      if (deps.fastify) techStack.frameworks.push('Fastify');
      if (deps.nest) techStack.frameworks.push('NestJS');

      // Detect payments
      if (deps.stripe || deps['@stripe/stripe-js']) {
        techStack.hasPayments = true;
      }

      // Detect package manager
      if (existsSync(path.join(repoPath, 'yarn.lock'))) {
        techStack.packageManager = 'yarn';
      } else if (existsSync(path.join(repoPath, 'pnpm-lock.yaml'))) {
        techStack.packageManager = 'pnpm';
      }
    }

    // Check for requirements.txt (Python)
    const requirementsPath = path.join(repoPath, 'requirements.txt');
    if (existsSync(requirementsPath)) {
      techStack.language = 'python';
      const requirements = readFileSync(requirementsPath, 'utf-8');

      if (requirements.includes('django')) techStack.frameworks.push('Django');
      if (requirements.includes('fastapi')) techStack.frameworks.push('FastAPI');
      if (requirements.includes('flask')) techStack.frameworks.push('Flask');
      if (requirements.includes('stripe')) techStack.hasPayments = true;
    }

    // Check for database
    if (existsSync(path.join(repoPath, 'prisma/schema.prisma'))) {
      techStack.database = 'PostgreSQL';
    } else if (existsSync(path.join(repoPath, 'docker-compose.yml'))) {
      const dockerCompose = readFileSync(
        path.join(repoPath, 'docker-compose.yml'),
        'utf-8'
      );
      if (dockerCompose.includes('postgres')) techStack.database = 'PostgreSQL';
      if (dockerCompose.includes('mysql')) techStack.database = 'MySQL';
      if (dockerCompose.includes('mongo')) techStack.database = 'MongoDB';
    }

    // Check for PII patterns
    await detectPII(repoPath, techStack);

    logger.info({ techStack }, 'Tech stack detected');

    return techStack;
  } catch (error) {
    logger.error({ error }, 'Error detecting tech stack');
    return techStack;
  }
}

const PII_PATTERNS = [
  /\bemail\b/i,
  /\bpassword\b/i,
  /\bname\b/i,
  /\baddress\b/i,
  /\bphone\b/i,
  /\bssn\b/i,
];
const PII_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go'];
const PII_MAX_FILES = 50;
const REVIEW_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx'];
const REVIEW_MAX_FILES = 500;

async function detectPII(repoPath: string, techStack: TechStack): Promise<void> {
  const files = await walkSourceFiles(repoPath, { extensions: PII_EXTENSIONS, maxFiles: PII_MAX_FILES });
  for (const file of files) {
    const content = await readSourceFile(file.absolute);
    if (content === null) continue;
    if (PII_PATTERNS.some((pattern) => pattern.test(content))) {
      techStack.hasPII = true;
      return;
    }
  }
}

export async function generateScopeDocument(
  techStack: TechStack,
  frameworks: ComplianceFramework[],
  scopeType: string
): Promise<ScopeDocument> {
  // Determine security level based on data types
  let securityLevel: 1 | 2 | 3 = 1;
  if (techStack.hasPayments || techStack.hasPII) {
    securityLevel = techStack.hasPayments ? 3 : 2;
  }

  // Determine applicable frameworks
  const applicableFrameworks = [...frameworks];

  if (techStack.hasPII) {
    if (!applicableFrameworks.includes('GDPR')) {
      applicableFrameworks.push('GDPR');
    }
  }

  if (techStack.hasPayments) {
    if (!applicableFrameworks.includes('PCI-DSS')) {
      applicableFrameworks.push('PCI-DSS');
    }
  }

  const scope: ScopeDocument = {
    repoUrl: '', // Will be filled by workflow
    techStack,
    securityLevel,
    frameworks: applicableFrameworks,
    inScope: [
      'Security & Compliance',
      'Performance & Scalability',
      'Reliability & Availability',
      'Observability',
      'Testing',
      'CI/CD',
    ],
    outOfScope:
      scopeType === 'security'
        ? ['Accessibility', 'SEO', 'Cost Optimization']
        : [],
    createdAt: new Date(),
  };

  return scope;
}

// ==================== CODE REVIEW ACTIVITY ====================

interface ReviewPattern {
  pattern: RegExp;
  name: string;
  severity: 'P0' | 'P1';
  secret: boolean;
}

const REVIEW_PATTERNS: ReviewPattern[] = [
  { pattern: /(password\s*[=:]\s*['"])([^'"\r\n]+)(['"])/gi, name: 'Hardcoded password', severity: 'P0', secret: true },
  { pattern: /(api[_-]?key\s*[=:]\s*['"])([^'"\r\n]+)(['"])/gi, name: 'Hardcoded API key', severity: 'P0', secret: true },
  { pattern: /(secret\s*[=:]\s*['"])([^'"\r\n]+)(['"])/gi, name: 'Hardcoded secret', severity: 'P0', secret: true },
  { pattern: /eval\s*\(/g, name: 'eval() usage', severity: 'P1', secret: false },
  { pattern: /innerHTML\s*=/g, name: 'innerHTML assignment', severity: 'P1', secret: false },
  { pattern: /document\.write\s*\(/g, name: 'document.write() usage', severity: 'P1', secret: false },
];

function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) {
    if (content.codePointAt(i) === 10) line++;
  }
  return line;
}

function safeFragment(match: RegExpMatchArray, secret: boolean): string {
  const raw = secret ? `${match[1]}[REDACTED]${match[3]}` : match[0];
  return redactSecrets(raw).text;
}

export async function reviewCriticalPaths(
  repoPath: string,
  criticalPaths: string[],
  checklist: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  logger.info({ criticalPaths, checklist }, 'Reviewing critical paths');

  for (const pathPattern of criticalPaths) {
    try {
      const needle = pathPattern.toLowerCase();
      const files = await walkSourceFiles(repoPath, {
        extensions: REVIEW_EXTENSIONS,
        maxFiles: REVIEW_MAX_FILES,
        filter: (relative) => relative.toLowerCase().includes(needle),
      });

      for (const file of files) {
        const content = await readSourceFile(file.absolute);
        if (content === null) continue;

        for (const { pattern, name, severity, secret } of REVIEW_PATTERNS) {
          const matches = [...content.matchAll(pattern)];
          if (matches.length === 0) continue;
          const line = lineOf(content, matches[0].index ?? 0);
          findings.push({
            id: `REVIEW-${findings.length + 1}`,
            title: name,
            description: `Found ${matches.length} occurrence(s) in ${file.relative}, first at line ${line}`,
            severity,
            category: 'security-code-review',
            evidence: [{
              type: 'code-review',
              file: file.relative,
              line,
              content: matches.slice(0, 3).map((m) => safeFragment(m, secret)).join('\n'),
              tool: 'code-review',
              timestamp: new Date(),
            }],
            remediation: {
              description: `Review and fix ${name.toLowerCase()} issues`,
              effort: 'hours',
              priority: severity === 'P0' ? 'immediate' : 'short-term',
            },
            verified: false,
            createdAt: new Date(),
          });
        }
      }
    } catch (error) {
      logger.warn({ error: String(error), pathPattern }, 'Failed to scan path');
    }
  }

  logger.info({ count: findings.length }, 'Code review completed');
  return findings;
}

// ==================== COMPLIANCE MAPPING ACTIVITY ====================

export async function mapToCompliance(
  findings: Finding[],
  frameworks: ComplianceFramework[]
): Promise<ComplianceMap[]> {
  const maps: ComplianceMap[] = [];

  for (const framework of frameworks) {
    const controls = await loadControls(framework);

    // Map findings to controls
    for (const control of controls) {
      const relevantFindings = findings.filter(
        f => f.category === control.category
      );

      const status =
        relevantFindings.length > 0 ? 'non-compliant' : 'unverified';

      control.evidence = relevantFindings.map(f => f.id);
      control.status = status;
    }

    const score =
      (controls.filter(c => c.status === 'compliant').length /
        controls.length) *
      100;

    maps.push({
      framework,
      controls,
      overallScore: score,
    });
  }

  return maps;
}

async function loadControls(framework: ComplianceFramework): Promise<any[]> {
  // Placeholder: Load controls from configuration
  const controls: any[] = [
    { id: 'A.8.1.1', title: 'User access management', category: 'security-auth', status: 'unverified' },
    { id: 'A.8.2.1', title: 'Access control', category: 'security-auth', status: 'unverified' },
    { id: 'A.8.3.1', title: 'Information access restriction', category: 'security-data', status: 'unverified' },
  ];

  return controls;
}

// ==================== CROSS-VALIDATION ACTIVITY ====================

export async function crossValidate(input: {
  findings: Finding[];
  complianceMaps: ComplianceMap[];
  model: string;
}): Promise<ReviewResult> {
  // This would integrate with Qwen Agent (different model) for review
  // For now, return placeholder result

  logger.info({ model: input.model, findingCount: input.findings.length }, 'Cross-validating findings');

  return {
    falsePositives: [],
    severityCorrections: [],
    missingFindings: [],
    reviewNotes: 'Automated review completed',
  };
}

// ==================== REPORT GENERATION ACTIVITY ====================

export async function generateReport(input: {
  repoUrl: string;
  workflowId: string;
  techStack: TechStack;
  scope: ScopeDocument;
  findings: Finding[];
  complianceMaps: ComplianceMap[];
  reviewResult: ReviewResult;
  outputDir?: string;
  outcome?: AuditOutcome;
  notPerformed?: NotPerformed[];
  scanners?: ScannerStatusEntry[];
  revision?: string | null;
  evidence?: { bundlePath: string; rootHash: string };
  signature?: ReportSignature;
  overrideAttempts?: OverrideAttempt[];
}): Promise<{ reportPath: string; evidencePath: string }> {
  const baseDir = input.outputDir || path.join('/tmp', `audit-${input.workflowId}`);
  const reportPath = path.join(baseDir, 'audit-report.md');
  const evidencePath = path.join(baseDir, 'evidence');

  // Create directories
  mkdirSync(baseDir, { recursive: true });
  mkdirSync(evidencePath, { recursive: true });

  // Generate markdown report
  const report = generateMarkdownReport(input);

  writeFileSync(reportPath, report);

  for (const finding of input.findings) {
    for (const evidence of finding.evidence) {
      const fileName = path.join(evidencePath, `${finding.id}.json`);
      const safe = {
        ...evidence,
        content: redactSecrets(evidence.content).text,
        ...(evidence.file === undefined ? {} : { file: redactSecrets(evidence.file).text }),
      };
      writeFileSync(fileName, JSON.stringify(safe, null, 2));
    }
  }

  if (input.outcome !== undefined || input.scanners !== undefined) {
    const status = {
      outcome: input.outcome,
      notPerformed: input.notPerformed ?? [],
      scanners: input.scanners ?? [],
      revision: input.revision ?? null,
    };
    writeFileSync(path.join(evidencePath, 'scanner-status.json'), JSON.stringify(status, null, 2));
  }

  logger.info({ reportPath, findingCount: input.findings.length }, 'Report generated');

  return { reportPath, evidencePath };
}

interface ReportInput {
  repoUrl: string;
  workflowId: string;
  techStack: TechStack;
  scope: ScopeDocument;
  findings: Finding[];
  complianceMaps: ComplianceMap[];
  outcome?: AuditOutcome;
  notPerformed?: NotPerformed[];
  scanners?: ScannerStatusEntry[];
  revision?: string | null;
  evidence?: { bundlePath: string; rootHash: string };
  signature?: ReportSignature;
  overrideAttempts?: OverrideAttempt[];
}

function productName(): string {
  const raw = Array.from(process.env.TESSERA_PRODUCT_NAME ?? '')
    .map((c) => ((c.codePointAt(0) ?? 0) < 32 || c.codePointAt(0) === 127 || '|#`*_[]<>'.includes(c) ? ' ' : c))
    .join('');
  const configured = raw.replace(/\s+/g, ' ').trim().slice(0, 64);
  return configured.length > 0 ? configured : 'Tessera';
}

function riskLevelFor(p0Count: number, p1Count: number, p2Count: number, outcome: ReportInput['outcome']): string {
  if (p0Count > 0) return 'CRITICAL';
  if (p1Count > 0) return 'HIGH';
  if (p2Count > 0) return 'MEDIUM';
  return outcome === 'incomplete' ? 'UNDETERMINED (audit incomplete)' : 'LOW';
}

function generateMarkdownReport(input: ReportInput): string {
  const p0Count = input.findings.filter((f: Finding) => f.severity === 'P0').length;
  const p1Count = input.findings.filter((f: Finding) => f.severity === 'P1').length;
  const p2Count = input.findings.filter((f: Finding) => f.severity === 'P2').length;
  const p3Count = input.findings.filter((f: Finding) => f.severity === 'P3').length;
  const riskLevel = riskLevelFor(p0Count, p1Count, p2Count, input.outcome);

  const outcomeBlock = renderOutcomeBlock({
    outcome: input.outcome,
    notPerformed: input.notPerformed,
    scanners: input.scanners,
    revision: input.revision,
    evidence: input.evidence,
    signature: input.signature,
    steering: steeringCounts(sanitizeOverrideAttempts(input.overrideAttempts)),
    findingCount: input.findings.length,
  });

  const report = `${outcomeBlock}
# Audit Report (${productName()})

**Repository:** ${input.repoUrl}
**Workflow ID:** ${input.workflowId}
**Date:** ${new Date().toISOString()}

## Executive Summary

- **Risk Level:** ${riskLevel}
- **Critical (P0):** ${p0Count}
- **High (P1):** ${p1Count}
- **Medium (P2):** ${p2Count}
- **Low (P3):** ${p3Count}

## Scope

**Tech Stack:** ${input.techStack.language} (${input.techStack.frameworks.join(', ')})
**Security Level:** ${input.scope.securityLevel}
**Frameworks:** ${input.scope.frameworks.join(', ')}

## Findings

| ID | Title | Severity | Category |
|----|-------|----------|----------|
${input.findings.map((f: Finding) => `| ${f.id} | ${f.title} | ${f.severity} | ${f.category} |`).join('\n')}

## Compliance

${input.complianceMaps.map((cm: ComplianceMap) => `### ${cm.framework}\n\nScore: ${cm.overallScore.toFixed(1)}%\n`).join('\n')}

## Generated by Temporal Audit Workflow
`;
  return redactSecrets(report).text;
}

// ==================== PERFORMANCE ACTIVITY (Lighthouse) ====================

export interface LighthouseResult {
  url: string;
  performance: number;
  accessibility: number;
  bestPractices: number;
  seo: number;
  lcp: number;
  fid: number;
  cls: number;
}

export async function runLighthouse(
  url: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: LighthouseResult }> {
  const findings: Finding[] = [];
  const outputPath = path.join('/tmp', `audit-${workflowId}`, 'lighthouse-report.json');

  logger.info({ url }, 'Running Lighthouse audit');

  // Ensure output directory exists
  const outputDir = path.dirname(outputPath);
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  try {
    // Run Lighthouse
    await execAsync(
      `lighthouse ${url} --output=json --output-path=${outputPath} --chrome-flags="--headless --no-sandbox"`,
      { timeout: 120000 }
    );

    // Parse report
    if (existsSync(outputPath)) {
      const report = JSON.parse(readFileSync(outputPath, 'utf-8'));

      const result: LighthouseResult = {
        url,
        performance: report.categories?.performance?.score * 100 || 0,
        accessibility: report.categories?.accessibility?.score * 100 || 0,
        bestPractices: report.categories?.['best-practices']?.score * 100 || 0,
        seo: report.categories?.seo?.score * 100 || 0,
        lcp: report.audits?.['largest-contentful-paint']?.numericValue || 0,
        fid: report.audits?.['max-potential-fid']?.numericValue || 0,
        cls: report.audits?.['cumulative-layout-shift']?.numericValue || 0,
      };

      // Generate findings based on thresholds
      if (result.performance < 50) {
        findings.push({
          id: 'LH-PERF-1',
          title: 'Poor Performance Score',
          description: `Performance score ${result.performance.toFixed(0)}% is below 50% threshold`,
          severity: 'P1',
          category: 'performance',
          evidence: [{
            type: 'scan-output',
            content: JSON.stringify(result, null, 2),
            tool: 'lighthouse',
            timestamp: new Date(),
          }],
          remediation: {
            description: 'Optimize images, reduce JavaScript, enable compression',
            effort: 'days',
            priority: 'short-term',
          },
          verified: true,
          createdAt: new Date(),
        });
      }

      // LCP finding
      if (result.lcp > 4000) {
        findings.push({
          id: 'LH-LCP-1',
          title: 'Largest Contentful Paint too slow',
          description: `LCP is ${(result.lcp / 1000).toFixed(2)}s (target: <2.5s)`,
          severity: 'P1',
          category: 'performance',
          evidence: [{
            type: 'scan-output',
            content: `LCP: ${result.lcp}ms`,
            tool: 'lighthouse',
            timestamp: new Date(),
          }],
          remediation: {
            description: 'Optimize server response time, use CDN, preload critical assets',
            effort: 'days',
            priority: 'short-term',
          },
          verified: true,
          createdAt: new Date(),
        });
      }

      // CLS finding
      if (result.cls > 0.25) {
        findings.push({
          id: 'LH-CLS-1',
          title: 'Cumulative Layout Shift too high',
          description: `CLS is ${result.cls.toFixed(3)} (target: <0.1)`,
          severity: 'P2',
          category: 'performance',
          evidence: [{
            type: 'scan-output',
            content: `CLS: ${result.cls}`,
            tool: 'lighthouse',
            timestamp: new Date(),
          }],
          remediation: {
            description: 'Add size attributes to images, reserve space for dynamic content',
            effort: 'hours',
            priority: 'medium-term',
          },
          verified: true,
          createdAt: new Date(),
        });
      }

      logger.info({ findings: findings.length, result }, 'Lighthouse completed');
      return { findings, result };
    }
  } catch (error) {
    logger.warn({ error: String(error) }, 'Lighthouse encountered issues');
  }

  return { findings, result: { url, performance: 0, accessibility: 0, bestPractices: 0, seo: 0, lcp: 0, fid: 0, cls: 0 } };
}

// ==================== ACCESSIBILITY ACTIVITY (axe-cli) ====================

export interface AccessibilityResult {
  url: string;
  violations: number;
  passes: number;
  incomplete: number;
}

export async function runAxeAccessibility(
  url: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: AccessibilityResult }> {
  const findings: Finding[] = [];
  const outputPath = path.join('/tmp', `audit-${workflowId}`, 'axe-report.json');

  logger.info({ url }, 'Running accessibility audit');

  // Ensure output directory exists
  const outputDir = path.dirname(outputPath);
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  try {
    // Run axe-cli
    await execAsync(
      `axe ${url} --save ${outputPath}`,
      { timeout: 60000 }
    );

    // Parse report
    if (existsSync(outputPath)) {
      const report = JSON.parse(readFileSync(outputPath, 'utf-8'));

      const result: AccessibilityResult = {
        url,
        violations: report.violations?.length || 0,
        passes: report.passes?.length || 0,
        incomplete: report.incomplete?.length || 0,
      };

      // Generate findings from violations
      for (const violation of report.violations || []) {
        const severity = violation.impact === 'critical' ? 'P0' :
                        violation.impact === 'serious' ? 'P1' :
                        violation.impact === 'moderate' ? 'P2' : 'P3';

        findings.push({
          id: `A11Y-${findings.length + 1}`,
          title: `Accessibility: ${violation.id}`,
          description: violation.description || violation.help,
          severity,
          category: 'accessibility' as any,
          evidence: [{
            type: 'scan-output',
            content: violation.nodes?.map((n: any) => n.html).slice(0, 3).join('\n') || '',
            tool: 'axe-cli',
            timestamp: new Date(),
          }],
          remediation: {
            description: violation.helpUrl || 'Fix accessibility issue',
            effort: 'hours',
            priority: severity === 'P0' ? 'immediate' : 'short-term',
          },
          verified: true,
          createdAt: new Date(),
        });
      }

      logger.info({ findings: findings.length, result }, 'Accessibility audit completed');
      return { findings, result };
    }
  } catch (error) {
    logger.warn({ error: String(error) }, 'Accessibility audit encountered issues');
  }

  return { findings, result: { url, violations: 0, passes: 0, incomplete: 0 } };
}

// ==================== SQL INJECTION ACTIVITY (Semgrep Custom Rules) ====================

export async function runSqlInjectionCheck(
  repoPath: string,
  workflowId: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const outputPath = path.join('/tmp', `audit-${workflowId}`, 'sql-injection-report.json');

  // Create custom SQL injection rules
  const rulesPath = '/tmp/sql-injection-rules.yaml';
  const rules = `
rules:
  - id: sql-injection-string-concat
    languages: [python, javascript, typescript]
    message: "SQL injection via string concatenation"
    severity: ERROR
    pattern: |
      $QUERY = "..." + $VAR + "..."

  - id: sql-injection-f-string
    languages: [python]
    message: "SQL injection via f-string"
    severity: ERROR
    pattern: |
      $QUERY = f"...{$VAR}..."

  - id: sql-injection-template-literal
    languages: [javascript, typescript]
    message: "SQL injection via template literal"
    severity: ERROR
    pattern: |
      $QUERY = \`...\${$VAR}...\`

  - id: sql-injection-exec
    languages: [python]
    message: "SQL injection in cursor.execute"
    severity: ERROR
    pattern: cursor.execute(f"...")

  - id: sql-injection-raw-query
    languages: [javascript, typescript]
    message: "Raw SQL query with user input"
    severity: WARNING
    pattern: |
      $DB.query("..." + $VAR)
`;

  writeFileSync(rulesPath, rules);

  logger.info({ repoPath }, 'Running SQL injection check');

  try {
    await execAsync(
      `semgrep --config=${rulesPath} --json --output ${outputPath} ${repoPath}`,
      { timeout: 120000 }
    );

    if (existsSync(outputPath)) {
      const report = JSON.parse(readFileSync(outputPath, 'utf-8'));

      for (const result of report.results || []) {
        findings.push({
          id: `SQL-${findings.length + 1}`,
          title: 'SQL Injection Vulnerability',
          description: result.extra?.message || 'Potential SQL injection detected',
          severity: 'P0',
          category: 'security-injection',
          evidence: [{
            type: 'code-snippet',
            file: result.path,
            line: result.start?.line,
            content: result.extra?.lines || '',
            tool: 'semgrep-sql',
            timestamp: new Date(),
          }],
          remediation: {
            description: 'Use parameterized queries or prepared statements',
            effort: 'hours',
            priority: 'immediate',
          },
          verified: true,
          createdAt: new Date(),
        });
      }
    }

    logger.info({ findings: findings.length }, 'SQL injection check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'SQL injection check encountered issues');
  }

  return findings;
}

// ==================== RELIABILITY ACTIVITY ====================

export interface ReliabilityResult {
  hasErrorHandling: boolean;
  hasRetryLogic: boolean;
  hasCircuitBreaker: boolean;
  hasHealthCheck: boolean;
  tryCatchCoverage: number;
}

export async function checkReliability(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: ReliabilityResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking reliability patterns');

  const result: ReliabilityResult = {
    hasErrorHandling: false,
    hasRetryLogic: false,
    hasCircuitBreaker: false,
    hasHealthCheck: false,
    tryCatchCoverage: 0,
  };

  try {
    // Find all code files
    const { stdout } = await execAsync(
      `find ${repoPath} -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.py" \\) | head -100`,
      { timeout: 30000 }
    );

    const files = stdout.trim().split('\n').filter(Boolean);
    let totalFiles = 0;
    let filesWithTryCatch = 0;

    for (const file of files) {
      if (!existsSync(file)) continue;
      totalFiles++;

      const content = readFileSync(file, 'utf-8');

      // Check for try-catch
      if (/try\s*{/.test(content) || /except\s*:/.test(content)) {
        filesWithTryCatch++;
        result.hasErrorHandling = true;
      }

      // Check for retry logic
      if (/retry|backoff|exponential/i.test(content)) {
        result.hasRetryLogic = true;
      }

      // Check for circuit breaker
      if (/circuit\s*breaker|breaker/i.test(content)) {
        result.hasCircuitBreaker = true;
      }

      // Check for health check
      if (/\/health|healthcheck|health_check/i.test(content)) {
        result.hasHealthCheck = true;
      }
    }

    result.tryCatchCoverage = totalFiles > 0 ? (filesWithTryCatch / totalFiles) * 100 : 0;

    // Generate findings
    if (!result.hasErrorHandling) {
      findings.push({
        id: 'REL-1',
        title: 'Missing Error Handling',
        description: 'No try-catch or error handling patterns found',
        severity: 'P1',
        category: 'reliability',
        evidence: [{
          type: 'code-review',
          content: 'No try-catch patterns detected in codebase',
          tool: 'reliability-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add try-catch blocks around critical operations',
          effort: 'days',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasRetryLogic) {
      findings.push({
        id: 'REL-2',
        title: 'Missing Retry Logic',
        description: 'No retry or backoff patterns found',
        severity: 'P2',
        category: 'reliability',
        evidence: [{
          type: 'code-review',
          content: 'No retry patterns detected',
          tool: 'reliability-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add retry logic for external API calls and database operations',
          effort: 'hours',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasHealthCheck) {
      findings.push({
        id: 'REL-3',
        title: 'Missing Health Check Endpoint',
        description: 'No /health or healthcheck endpoint found',
        severity: 'P2',
        category: 'reliability',
        evidence: [{
          type: 'code-review',
          content: 'No health check endpoint detected',
          tool: 'reliability-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add /health endpoint for monitoring',
          effort: 'hours',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (result.tryCatchCoverage < 50) {
      findings.push({
        id: 'REL-4',
        title: 'Low Error Handling Coverage',
        description: `Only ${result.tryCatchCoverage.toFixed(0)}% of files have error handling`,
        severity: 'P2',
        category: 'reliability',
        evidence: [{
          type: 'code-review',
          content: `Try-catch coverage: ${result.tryCatchCoverage.toFixed(1)}%`,
          tool: 'reliability-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Increase error handling coverage to at least 80%',
          effort: 'days',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    logger.info({ findings: findings.length, result }, 'Reliability check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'Reliability check encountered issues');
  }

  return { findings, result };
}

// ==================== OBSERVABILITY ACTIVITY ====================

export interface ObservabilityResult {
  hasStructuredLogging: boolean;
  hasMetrics: boolean;
  hasTracing: boolean;
  hasAlerting: boolean;
  loggingFramework: string | null;
}

export async function checkObservability(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: ObservabilityResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking observability patterns');

  const result: ObservabilityResult = {
    hasStructuredLogging: false,
    hasMetrics: false,
    hasTracing: false,
    hasAlerting: false,
    loggingFramework: null,
  };

  try {
    const { stdout } = await execAsync(
      `find ${repoPath} -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.py" \\) | head -100`,
      { timeout: 30000 }
    );

    const files = stdout.trim().split('\n').filter(Boolean);

    for (const file of files) {
      if (!existsSync(file)) continue;
      const content = readFileSync(file, 'utf-8');

      // Check for structured logging
      if (/pino|winston|bunyan|structlog|loguru/i.test(content)) {
        result.hasStructuredLogging = true;
        if (/pino/i.test(content)) result.loggingFramework = 'pino';
        else if (/winston/i.test(content)) result.loggingFramework = 'winston';
        else if (/bunyan/i.test(content)) result.loggingFramework = 'bunyan';
        else if (/structlog/i.test(content)) result.loggingFramework = 'structlog';
        else if (/loguru/i.test(content)) result.loggingFramework = 'loguru';
      }

      // Check for metrics
      if (/prometheus|metrics|statsd|datadog|newrelic/i.test(content)) {
        result.hasMetrics = true;
      }

      // Check for tracing
      if (/opentelemetry|jaeger|zipkin|tracing/i.test(content)) {
        result.hasTracing = true;
      }

      // Check for alerting
      if (/alertmanager|pagerduty|opsgenie|alerting/i.test(content)) {
        result.hasAlerting = true;
      }
    }

    // Generate findings
    if (!result.hasStructuredLogging) {
      findings.push({
        id: 'OBS-1',
        title: 'Missing Structured Logging',
        description: 'No structured logging framework detected (pino, winston, structlog)',
        severity: 'P1',
        category: 'observability',
        evidence: [{
          type: 'code-review',
          content: 'No structured logging framework found',
          tool: 'observability-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Implement structured logging with JSON output',
          effort: 'days',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasMetrics) {
      findings.push({
        id: 'OBS-2',
        title: 'Missing Metrics Collection',
        description: 'No metrics instrumentation found',
        severity: 'P2',
        category: 'observability',
        evidence: [{
          type: 'code-review',
          content: 'No metrics framework detected',
          tool: 'observability-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add Prometheus or similar metrics collection',
          effort: 'days',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasTracing) {
      findings.push({
        id: 'OBS-3',
        title: 'Missing Distributed Tracing',
        description: 'No distributed tracing implementation found',
        severity: 'P2',
        category: 'observability',
        evidence: [{
          type: 'code-review',
          content: 'No tracing framework detected',
          tool: 'observability-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Implement OpenTelemetry for distributed tracing',
          effort: 'days',
          priority: 'long-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    logger.info({ findings: findings.length, result }, 'Observability check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'Observability check encountered issues');
  }

  return { findings, result };
}

// ==================== CI/CD ACTIVITY ====================

export interface CicdResult {
  hasCiPipeline: boolean;
  hasSecurityGates: boolean;
  hasDeployStage: boolean;
  hasRollback: boolean;
  platform: string | null;
}

export async function checkCicd(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: CicdResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking CI/CD configuration');

  const result: CicdResult = {
    hasCiPipeline: false,
    hasSecurityGates: false,
    hasDeployStage: false,
    hasRollback: false,
    platform: null,
  };

  try {
    // Check for CI config files
    const ciFiles = [
      { path: '.woodpecker.yml', platform: 'woodpecker' },
      { path: '.github/workflows', platform: 'github-actions' },
      { path: '.gitlab-ci.yml', platform: 'gitlab-ci' },
      { path: 'Jenkinsfile', platform: 'jenkins' },
      { path: '.circleci/config.yml', platform: 'circleci' },
    ];

    for (const { path: ciPath, platform } of ciFiles) {
      const fullPath = path.join(repoPath, ciPath);
      if (existsSync(fullPath)) {
        result.hasCiPipeline = true;
        result.platform = platform;

        // Read config
        if (ciPath.endsWith('.yml') || ciPath.endsWith('.yaml')) {
          const content = readFileSync(fullPath, 'utf-8');

          // Check for security gates
          if (/npm\s+audit|gitleaks|semgrep|snyk|trivy/i.test(content)) {
            result.hasSecurityGates = true;
          }

          // Check for deploy stage
          if (/deploy|publish|release/i.test(content)) {
            result.hasDeployStage = true;
          }

          // Check for rollback
          if (/rollback|revert|undo/i.test(content)) {
            result.hasRollback = true;
          }
        }
        break;
      }
    }

    // Generate findings
    if (!result.hasCiPipeline) {
      findings.push({
        id: 'CICD-1',
        title: 'Missing CI/CD Pipeline',
        description: 'No CI pipeline configuration found',
        severity: 'P1',
        category: 'cicd',
        evidence: [{
          type: 'config',
          content: 'No .woodpecker.yml, .github/workflows, or other CI config found',
          tool: 'cicd-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add CI pipeline with build, test, and security gates',
          effort: 'days',
          priority: 'immediate',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (result.hasCiPipeline && !result.hasSecurityGates) {
      findings.push({
        id: 'CICD-2',
        title: 'Missing Security Gates in CI',
        description: 'CI pipeline lacks security scanning (npm audit, gitleaks, semgrep)',
        severity: 'P1',
        category: 'cicd',
        evidence: [{
          type: 'config',
          content: `CI platform: ${result.platform}, no security gates found`,
          tool: 'cicd-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add npm audit, gitleaks, and semgrep to CI pipeline',
          effort: 'hours',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (result.hasCiPipeline && !result.hasRollback) {
      findings.push({
        id: 'CICD-3',
        title: 'Missing Rollback Procedure',
        description: 'CI pipeline lacks rollback mechanism',
        severity: 'P2',
        category: 'cicd',
        evidence: [{
          type: 'config',
          content: 'No rollback or revert steps found in CI config',
          tool: 'cicd-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add automated rollback procedure for failed deployments',
          effort: 'hours',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    logger.info({ findings: findings.length, result }, 'CI/CD check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'CI/CD check encountered issues');
  }

  return { findings, result };
}

// ==================== HUMAN APPROVAL ACTIVITY ====================

export async function waitForHumanApproval(
  workflowId: string,
  p0Count: number,
  deadline?: string
): Promise<{ approved: boolean; reviewer?: string; notes?: string }> {
  logger.info({ workflowId, p0Count }, 'Waiting for human approval');

  // In a real Temporal workflow, this would use signals
  // For now, auto-approve if no P0 findings or skip flag
  if (p0Count === 0) {
    logger.info('Auto-approved: no critical findings');
    return { approved: true, reviewer: 'auto', notes: 'No P0 findings' };
  }

  // In production, this would await a signal from the client
  // For now, return pending state
  return { approved: false, notes: 'Requires manual review' };
}

// ==================== CODE QUALITY ACTIVITY ====================

export interface CodeQualityResult {
  lintErrors: number;
  lintWarnings: number;
  typeErrors: number;
  complexityIssues: number;
  techDebtScore: number;
}

export async function checkCodeQuality(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: CodeQualityResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking code quality');

  const result: CodeQualityResult = {
    lintErrors: 0,
    lintWarnings: 0,
    typeErrors: 0,
    complexityIssues: 0,
    techDebtScore: 0,
  };

  try {
    // Check for ESLint config
    const eslintConfig = [
      path.join(repoPath, '.eslintrc.js'),
      path.join(repoPath, '.eslintrc.json'),
      path.join(repoPath, '.eslintrc'),
    ];

    const hasEslint = eslintConfig.some(c => existsSync(c));

    if (hasEslint) {
      // Run ESLint
      try {
        const { stdout, stderr } = await execAsync(
          `cd ${repoPath} && npx eslint . --ext .js,.ts,.jsx,.tsx --format json`,
          { timeout: 60000 }
        );

        const lintResults = JSON.parse(stdout || '[]');

        for (const fileResult of lintResults) {
          for (const msg of fileResult.messages || []) {
            if (msg.severity === 2) {
              result.lintErrors++;
            } else {
              result.lintWarnings++;
            }
          }
        }

        if (result.lintErrors > 0) {
          findings.push({
            id: 'QUALITY-1',
            title: 'Linting Errors',
            description: `${result.lintErrors} ESLint errors found`,
            severity: 'P1',
            category: 'code-quality' as any,
            evidence: [{
              type: 'scan-output',
              content: `Lint errors: ${result.lintErrors}, warnings: ${result.lintWarnings}`,
              tool: 'eslint',
              timestamp: new Date(),
            }],
            remediation: {
              description: 'Fix ESLint errors before committing',
              effort: 'hours',
              priority: 'short-term',
            },
            verified: true,
            createdAt: new Date(),
          });
        }
      } catch (error: any) {
        // ESLint exits with non-zero on errors - parse the output
        const output = error.stdout || '';
        try {
          const lintResults = JSON.parse(output);
          for (const fileResult of lintResults) {
            for (const msg of fileResult.messages || []) {
              if (msg.severity === 2) result.lintErrors++;
              else result.lintWarnings++;
            }
          }
        } catch {
          // Ignore parse errors
        }
      }
    }

    // Check for TypeScript
    const tsconfigPath = path.join(repoPath, 'tsconfig.json');
    if (existsSync(tsconfigPath)) {
      try {
        const { stdout } = await execAsync(
          `cd ${repoPath} && npx tsc --noEmit 2>&1 | grep -c "error TS"`,
          { timeout: 60000 }
        );
        result.typeErrors = Number.parseInt(stdout.trim()) || 0;

        if (result.typeErrors > 0) {
          findings.push({
            id: 'QUALITY-2',
            title: 'TypeScript Errors',
            description: `${result.typeErrors} TypeScript errors found`,
            severity: 'P1',
            category: 'code-quality' as any,
            evidence: [{
              type: 'scan-output',
              content: `Type errors: ${result.typeErrors}`,
              tool: 'tsc',
              timestamp: new Date(),
            }],
            remediation: {
              description: 'Fix TypeScript type errors',
              effort: 'hours',
              priority: 'short-term',
            },
            verified: true,
            createdAt: new Date(),
          });
        }
      } catch {
        // TypeScript errors cause non-zero exit
      }
    }

    // Check code complexity (simple heuristic)
    const { stdout: fileStats } = await execAsync(
      `find ${repoPath} -type f \\( -name "*.js" -o -name "*.ts" \\) -exec wc -l {} \\; | sort -rn | head -20`,
      { timeout: 30000 }
    );

    const longFiles = fileStats.trim().split('\n').filter(line => {
      const lines = Number.parseInt(line.split(' ')[0]);
      return lines > 500;
    });

    result.complexityIssues = longFiles.length;

    if (result.complexityIssues > 0) {
      findings.push({
        id: 'QUALITY-3',
        title: 'High Code Complexity',
        description: `${result.complexityIssues} files exceed 500 lines`,
        severity: 'P2',
        category: 'code-quality' as any,
        evidence: [{
          type: 'scan-output',
          content: longFiles.slice(0, 5).join('\n'),
          tool: 'wc',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Consider refactoring large files into smaller modules',
          effort: 'days',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    // Calculate tech debt score (simple metric)
    result.techDebtScore = result.lintErrors * 10 + result.typeErrors * 5 + result.complexityIssues * 3;

    logger.info({ findings: findings.length, result }, 'Code quality check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'Code quality check encountered issues');
  }

  return { findings, result };
}

// ==================== DOCUMENTATION ACTIVITY ====================

export interface DocumentationResult {
  hasReadme: boolean;
  hasApiDocs: boolean;
  hasArchitecture: boolean;
  hasRunbooks: boolean;
  docScore: number;
}

export async function checkDocumentation(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: DocumentationResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking documentation');

  const result: DocumentationResult = {
    hasReadme: false,
    hasApiDocs: false,
    hasArchitecture: false,
    hasRunbooks: false,
    docScore: 0,
  };

  try {
    // Check for README
    const readmePaths = [
      path.join(repoPath, 'README.md'),
      path.join(repoPath, 'readme.md'),
      path.join(repoPath, 'README'),
    ];

    result.hasReadme = readmePaths.some(p => existsSync(p));

    if (!result.hasReadme) {
      findings.push({
        id: 'DOC-1',
        title: 'Missing README',
        description: 'No README.md found in repository root',
        severity: 'P1',
        category: 'documentation' as any,
        evidence: [{
          type: 'config',
          content: 'No README.md, readme.md, or README file found',
          tool: 'doc-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add README.md with project description, setup instructions, and usage',
          effort: 'hours',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    } else {
      // Check README completeness
      const readmePath = readmePaths.find(p => existsSync(p));
      if (readmePath) {
        const content = readFileSync(readmePath, 'utf-8');
        const hasInstall = /install|setup|getting started/i.test(content);
        const hasUsage = /usage|example|how to/i.test(content);

        if (!hasInstall || !hasUsage) {
          findings.push({
            id: 'DOC-2',
            title: 'Incomplete README',
            description: 'README missing installation or usage sections',
            severity: 'P2',
            category: 'documentation' as any,
            evidence: [{
              type: 'config',
              content: `Has install: ${hasInstall}, Has usage: ${hasUsage}`,
              tool: 'doc-check',
              timestamp: new Date(),
            }],
            remediation: {
              description: 'Add installation and usage sections to README',
              effort: 'hours',
              priority: 'short-term',
            },
            verified: true,
            createdAt: new Date(),
          });
        }
      }
    }

    // Check for API docs
    const apiDocPaths = [
      path.join(repoPath, 'docs', 'api'),
      path.join(repoPath, 'api', 'README.md'),
      path.join(repoPath, 'openapi.yaml'),
      path.join(repoPath, 'openapi.json'),
      path.join(repoPath, 'swagger.yaml'),
    ];

    result.hasApiDocs = apiDocPaths.some(p => existsSync(p));

    // Check for architecture docs
    const archDocPaths = [
      path.join(repoPath, 'docs', 'architecture'),
      path.join(repoPath, 'ARCHITECTURE.md'),
      path.join(repoPath, 'docs', 'ADR'),
    ];

    result.hasArchitecture = archDocPaths.some(p => existsSync(p));

    // Check for runbooks
    const runbookPaths = [
      path.join(repoPath, 'docs', 'runbooks'),
      path.join(repoPath, 'RUNBOOK.md'),
      path.join(repoPath, 'docs', 'operations'),
    ];

    result.hasRunbooks = runbookPaths.some(p => existsSync(p));

    // Calculate doc score
    result.docScore = (result.hasReadme ? 40 : 0) +
                       (result.hasApiDocs ? 20 : 0) +
                       (result.hasArchitecture ? 20 : 0) +
                       (result.hasRunbooks ? 20 : 0);

    logger.info({ findings: findings.length, result }, 'Documentation check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'Documentation check encountered issues');
  }

  return { findings, result };
}

// ==================== PRIVACY & GDPR ACTIVITY ====================

export interface PrivacyResult {
  hasConsentBanner: boolean;
  hasPrivacyPolicy: boolean;
  hasDataClassification: boolean;
  hasCookieConfig: boolean;
}

export async function checkPrivacy(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: PrivacyResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking privacy & GDPR');

  const result: PrivacyResult = {
    hasConsentBanner: false,
    hasPrivacyPolicy: false,
    hasDataClassification: false,
    hasCookieConfig: false,
  };

  try {
    // Find code files
    const { stdout } = await execAsync(
      `find ${repoPath} -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" -o -name "*.py" \\) | head -100`,
      { timeout: 30000 }
    );

    const files = stdout.trim().split('\n').filter(Boolean);

    for (const file of files) {
      if (!existsSync(file)) continue;
      const content = readFileSync(file, 'utf-8');

      // Check for consent banner implementation
      if (/consent|cookie.*banner|gdpr.*banner|privacy.*banner/i.test(content)) {
        result.hasConsentBanner = true;
      }

      // Check for privacy policy
      if (/privacy.?policy|privacypolicy/i.test(content)) {
        result.hasPrivacyPolicy = true;
      }

      // Check for data classification
      if (/data.?classification|pii.?identif|sensitive.?data/i.test(content)) {
        result.hasDataClassification = true;
      }

      // Check for cookie configuration
      if (/cookie.?consent|cookiebot|cookie.?law/i.test(content)) {
        result.hasCookieConfig = true;
      }
    }

    // Generate findings
    if (!result.hasConsentBanner) {
      findings.push({
        id: 'PRIV-1',
        title: 'Missing Consent Banner',
        description: 'No cookie consent implementation detected',
        severity: 'P1',
        category: 'privacy' as any,
        evidence: [{
          type: 'code-review',
          content: 'No consent banner or cookie consent library found',
          tool: 'privacy-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Implement cookie consent banner (Cookiebot, OneTrust, or custom)',
          effort: 'days',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasPrivacyPolicy) {
      findings.push({
        id: 'PRIV-2',
        title: 'Missing Privacy Policy',
        description: 'No privacy policy reference found',
        severity: 'P1',
        category: 'privacy' as any,
        evidence: [{
          type: 'code-review',
          content: 'No privacy policy link or page detected',
          tool: 'privacy-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add privacy policy page and link in footer/consent flow',
          effort: 'hours',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    logger.info({ findings: findings.length, result }, 'Privacy check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'Privacy check encountered issues');
  }

  return { findings, result };
}

// ==================== FUNCTIONAL REQUIREMENTS ACTIVITY ====================

export interface FunctionalResult {
  hasAcceptanceCriteria: boolean;
  hasTestsPerFeature: boolean;
  hasEdgeCaseTests: boolean;
  hasErrorPathTests: boolean;
}

export async function checkFunctionalRequirements(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: FunctionalResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking functional requirements');

  const result: FunctionalResult = {
    hasAcceptanceCriteria: false,
    hasTestsPerFeature: false,
    hasEdgeCaseTests: false,
    hasErrorPathTests: false,
  };

  try {
    // Check for feature specs / acceptance criteria
    const specPaths = [
      path.join(repoPath, 'specs'),
      path.join(repoPath, 'features'),
      path.join(repoPath, '.feature'),
      path.join(repoPath, 'requirements'),
    ];

    result.hasAcceptanceCriteria = specPaths.some(p => existsSync(p));

    // Check for test files
    const testDirs = [
      path.join(repoPath, 'tests'),
      path.join(repoPath, 'test'),
      path.join(repoPath, '__tests__'),
      path.join(repoPath, 'spec'),
    ];

    const hasTests = testDirs.some(p => existsSync(p));

    if (hasTests) {
      // Check test content for edge cases
      const { stdout: testFiles } = await execAsync(
        `find ${repoPath} -path "*/tests/*" -o -path "*/test/*" -o -path "*/__tests__/*" | grep -E "\\.(test|spec)\\.(js|ts|py)$" | head -50`,
        { timeout: 30000 }
      );

      const testFileList = testFiles.trim().split('\n').filter(Boolean);

      if (testFileList.length > 0) {
        result.hasTestsPerFeature = true;

        // Check for edge case tests
        for (const file of testFileList.slice(0, 20)) {
          if (!existsSync(file)) continue;
          const content = readFileSync(file, 'utf-8');

          if (/edge.?case|boundary|corner.?case|negative.?test/i.test(content)) {
            result.hasEdgeCaseTests = true;
          }

          if (/error.?path|error.?case|exception.?test|fail.?test/i.test(content)) {
            result.hasErrorPathTests = true;
          }
        }
      }
    }

    // Generate findings
    if (!result.hasAcceptanceCriteria) {
      findings.push({
        id: 'FUNC-1',
        title: 'Missing Acceptance Criteria',
        description: 'No feature specs or acceptance criteria documentation found',
        severity: 'P1',
        category: 'compliance' as any,
        evidence: [{
          type: 'config',
          content: 'No specs/, features/, or requirements/ directory found',
          tool: 'functional-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Document acceptance criteria for each feature (Gherkin, markdown, or specs)',
          effort: 'days',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasEdgeCaseTests) {
      findings.push({
        id: 'FUNC-2',
        title: 'Missing Edge Case Tests',
        description: 'No edge case or boundary tests found',
        severity: 'P2',
        category: 'testing' as any,
        evidence: [{
          type: 'code-review',
          content: 'No test files mention edge cases, boundaries, or corner cases',
          tool: 'functional-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Add tests for edge cases and boundary conditions',
          effort: 'days',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    logger.info({ findings: findings.length, result }, 'Functional requirements check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'Functional requirements check encountered issues');
  }

  return { findings, result };
}

// ==================== BLINDE VLEKKEN ACTIVITY ====================

export interface BlindSpotsResult {
  hasOnCall: boolean;
  busFactor: number;
  hasDataLineage: boolean;
  hasVendorPolicy: boolean;
  hasExitStrategy: boolean;
  hasMobileSupport: boolean;
  hasI18n: boolean;
  riskScore: number;
}

export async function checkBlindSpots(
  repoPath: string,
  workflowId: string
): Promise<{ findings: Finding[]; result: BlindSpotsResult }> {
  const findings: Finding[] = [];

  logger.info({ repoPath }, 'Checking blind spots');

  const result: BlindSpotsResult = {
    hasOnCall: false,
    busFactor: 0,
    hasDataLineage: false,
    hasVendorPolicy: false,
    hasExitStrategy: false,
    hasMobileSupport: false,
    hasI18n: false,
    riskScore: 0,
  };

  try {
    // Check for on-call documentation
    const onCallPaths = [
      path.join(repoPath, 'docs', 'on-call'),
      path.join(repoPath, 'ONCALL.md'),
      path.join(repoPath, '.oncall'),
    ];
    result.hasOnCall = onCallPaths.some(p => existsSync(p));

    // Check bus factor (number of contributors)
    try {
      const { stdout } = await execAsync(
        `cd ${repoPath} && git log --format='%aN' | sort -u | wc -l`,
        { timeout: 10000 }
      );
      result.busFactor = Number.parseInt(stdout.trim()) || 1;
    } catch {
      result.busFactor = 1;
    }

    // Check for data lineage
    const { stdout: lineageCheck } = await execAsync(
      `find ${repoPath} -type f \\( -name "*.md" -o -name "*.txt" \\) -exec grep -l "data.*lineage\\|data.*flow\\|lineage" {} \\; 2>/dev/null | head -5`,
      { timeout: 30000 }
    );
    result.hasDataLineage = lineageCheck.trim().length > 0;

    // Check for vendor policy
    const vendorPaths = [
      path.join(repoPath, 'docs', 'vendor'),
      path.join(repoPath, 'VENDOR.md'),
    ];
    result.hasVendorPolicy = vendorPaths.some(p => existsSync(p));

    // Check for exit strategy
    const exitPaths = [
      path.join(repoPath, 'docs', 'exit-strategy'),
      path.join(repoPath, 'EXIT-STRATEGY.md'),
      path.join(repoPath, 'docs', 'sunset'),
    ];
    result.hasExitStrategy = exitPaths.some(p => existsSync(p));

    // Check for mobile support (responsive)
    const { stdout: codeFiles } = await execAsync(
      `find ${repoPath} -type f \\( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" \\) | head -50`,
      { timeout: 30000 }
    );

    const files = codeFiles.trim().split('\n').filter(Boolean);
    for (const file of files.slice(0, 20)) {
      if (!existsSync(file)) continue;
      const content = readFileSync(file, 'utf-8');

      // Check for mobile/responsive
      if (/mobile|responsive|viewport|@media|max-width/i.test(content)) {
        result.hasMobileSupport = true;
      }

      // Check for i18n
      if (/i18n|locale|translation|language|intl/i.test(content)) {
        result.hasI18n = true;
      }
    }

    // Generate findings
    if (result.busFactor <= 1) {
      findings.push({
        id: 'BLIND-1',
        title: 'Bus Factor Risk',
        description: `Only ${result.busFactor} contributor(s) - knowledge concentration risk`,
        severity: 'P1',
        category: 'compliance' as any,
        evidence: [{
          type: 'scan-output',
          content: `Unique contributors: ${result.busFactor}`,
          tool: 'blind-spots-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Document critical knowledge, cross-train team members',
          effort: 'days',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasOnCall) {
      findings.push({
        id: 'BLIND-2',
        title: 'Missing On-Call Documentation',
        description: 'No on-call procedures documented',
        severity: 'P2',
        category: 'observability' as any,
        evidence: [{
          type: 'config',
          content: 'No docs/on-call, ONCALL.md, or .oncall found',
          tool: 'blind-spots-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Document on-call procedures, escalation paths, and runbooks',
          effort: 'hours',
          priority: 'short-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    if (!result.hasExitStrategy) {
      findings.push({
        id: 'BLIND-3',
        title: 'Missing Exit Strategy',
        description: 'No sunset/exit strategy documented',
        severity: 'P3',
        category: 'compliance' as any,
        evidence: [{
          type: 'config',
          content: 'No exit strategy documentation found',
          tool: 'blind-spots-check',
          timestamp: new Date(),
        }],
        remediation: {
          description: 'Document data export procedures and vendor exit strategy',
          effort: 'hours',
          priority: 'medium-term',
        },
        verified: true,
        createdAt: new Date(),
      });
    }

    // Calculate risk score
    result.riskScore = (result.busFactor <= 1 ? 30 : 0) +
                       (!result.hasOnCall ? 20 : 0) +
                       (!result.hasDataLineage ? 15 : 0) +
                       (!result.hasVendorPolicy ? 15 : 0) +
                       (!result.hasExitStrategy ? 10 : 0);

    logger.info({ findings: findings.length, result }, 'Blind spots check completed');
  } catch (error) {
    logger.warn({ error: String(error) }, 'Blind spots check encountered issues');
  }

  return { findings, result };
}

// ==================== NEW NFR ACTIVITIES (ISO 25010) ====================

/**
 * Helper function to create Evidence object from string
 */
function createEvidence(content: string, tool: string = 'manual'): Evidence {
  return {
    type: 'scan-output',
    content,
    tool,
    timestamp: new Date(),
  };
}

/**
 * Helper function to create Remediation object
 */
function createRemediation(description: string, priority: 'immediate' | 'short-term' | 'medium-term' | 'long-term' = 'short-term', effort: 'hours' | 'days' | 'weeks' = 'hours'): Remediation {
  return {
    description,
    effort,
    priority,
  };
}

/**
 * Throughput Testing Activity (ISO 25010 §6.1.1)
 * Measures requests/sec, transactions/sec under load using k6
 */
export async function measureThroughput(
  testScript: string,
  targetUrl: string,
  duration: string = '5m',
  targetRPS: number = 100
): Promise<{ findings: Finding[]; throughput: number; result: string }> {
  logger.info({ targetUrl, duration, targetRPS }, 'Starting throughput test');

  const findings: Finding[] = [];
  const result = 'PASSED';
  let throughput = 0;
  let tmpDir: string | undefined;

  try {
    // Check if k6 is available
    try {
      await execAsync('k6 version', { timeout: 5000 });
    } catch {
      findings.push({
        id: 'throughput-001',
        category: 'performance',
        severity: 'P2',
        title: 'k6 not installed',
        description: 'k6 load testing tool is not installed. Install with: go install go.k6.io/k6@latest',
        evidence: [createEvidence('Tool check failed', 'tool-check')],
        remediation: createRemediation('Install k6 for throughput testing'),
        verified: true,
        createdAt: new Date(),
      });

      return { findings, throughput, result: 'SKIPPED' };
    }

    // Run k6 throughput test
    const k6Script = `
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  scenarios: {
    constant_throughput: {
      executor: 'constant-arrival-rate',
      rate: ${targetRPS},
      timeUnit: '1s',
      duration: '${duration}',
      preAllocatedVUs: 10,
    },
  },
};

export default function () {
  const res = http.get('${targetUrl}');
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
}
`;

    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tessera-k6-'));
    const scriptPath = path.join(tmpDir, 'throughput-test.js');
    const resultsPath = path.join(tmpDir, 'throughput-results.json');
    await fs.writeFile(scriptPath, k6Script);

    await execAsync(
      `k6 run --out json=${resultsPath} ${scriptPath}`,
      { timeout: 600000 } // 10 min timeout
    );

    // Parse results
    const resultsJson = await fs.readFile(resultsPath, 'utf-8');
    const lines = resultsJson.trim().split('\n');
    const dataPoints = lines.map(line => JSON.parse(line));

    // Calculate throughput
    const httpMetrics = dataPoints.filter(d => d.type === 'Point' && d.metric === 'http_reqs');
    const totalRequests = httpMetrics.length;
    const testDuration = Number.parseInt(duration) || 300; // seconds
    throughput = totalRequests / testDuration;

    // Check if throughput meets target
    if (throughput < targetRPS * 0.8) {
      findings.push({
        id: 'throughput-002',
        category: 'performance',
        severity: 'P1',
        title: 'Throughput below target',
        description: `Achieved ${throughput.toFixed(2)} req/s, target is ${targetRPS} req/s`,
        evidence: [createEvidence(`Throughput: ${throughput.toFixed(2)} req/s`, 'k6')],
        remediation: createRemediation('Optimize application performance or increase resources', 'medium-term', 'weeks'),
        verified: true,
        createdAt: new Date(),
      });
    }

    // Cleanup
    await fs.rm(tmpDir, { recursive: true, force: true });

    logger.info({ throughput, findingsCount: findings.length }, 'Throughput test completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage }, 'Throughput test failed');
    findings.push({
      id: 'throughput-003',
      category: 'performance',
      severity: 'P2',
      title: 'Throughput test failed',
      description: errorMessage,
      evidence: [createEvidence(errorMessage, 'error')],
      remediation: createRemediation('Check k6 installation and test configuration'),
      verified: true,
      createdAt: new Date(),
    });
  }

  return { findings, throughput, result };
}

/**
 * Durability Assessment Activity (ISO 25010 §4.5)
 * Checks data integrity, backup strategies, and fault recovery
 */
export async function assessDurability(
  repoPath: string,
  requiredRetentionDays: number = 30
): Promise<{ findings: Finding[]; durabilityScore: number; result: string }> {
  logger.info({ repoPath, requiredRetentionDays }, 'Assessing durability');

  const findings: Finding[] = [];
  let durabilityScore = 100;

  try {
    // Check for data integrity patterns (checksum, validation, replication)
    const integrityPatterns = [
      { pattern: 'checksum|hash|md5|sha256', name: 'Checksum verification' },
      { pattern: 'validate|validation|schema', name: 'Data validation' },
      { pattern: 'replica|replication|mirror', name: 'Data replication' },
      { pattern: 'backup|snapshot|dump', name: 'Backup strategy' },
    ];

    for (const { pattern, name } of integrityPatterns) {
      const { stdout } = await execAsync(
        `grep -r "${pattern}" ${repoPath} --include="*.ts" --include="*.js" --include="*.py" | head -5 || true`,
        { timeout: 30000 }
      );

      if (!stdout || stdout.trim().length === 0) {
        durabilityScore -= 15;
        findings.push({
          id: `durability-${name.toLowerCase().replace(/\s+/g, '-')}`,
          category: 'reliability',
          severity: 'P1',
          title: `Missing ${name.toLowerCase()}`,
          description: `No ${name.toLowerCase()} patterns detected in codebase`,
          evidence: [createEvidence('Grep search returned no results', 'grep')],
          remediation: createRemediation(`Implement ${name.toLowerCase()} for data durability`),
          verified: true,
          createdAt: new Date(),
        });
      }
    }

    logger.info({ durabilityScore, findingsCount: findings.length }, 'Durability assessment completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage }, 'Durability assessment failed');
  }

  return {
    findings,
    durabilityScore,
    result: durabilityScore >= 70 ? 'PASSED' : 'NEEDS_ATTENTION'
  };
}

/**
 * Stability Assessment Activity (ISO 25010 §4.6)
 * Detects crash-prone patterns, memory leaks, unhandled errors
 */
export async function assessStability(
  repoPath: string
): Promise<{ findings: Finding[]; stabilityScore: number; result: string }> {
  logger.info({ repoPath }, 'Assessing stability');

  const findings: Finding[] = [];
  let stabilityScore = 100;

  try {
    // Check for crash-prone patterns
    const crashPatterns = [
      { pattern: String.raw`process\.exit`, name: 'process.exit calls', severity: 'P1' },
      { pattern: String.raw`throw\s+new\s+Error`, name: 'unhandled throws', severity: 'P2' },
      { pattern: 'unhandledRejection', name: 'unhandled rejection handlers', severity: 'P1' },
      { pattern: 'uncaughtException', name: 'uncaught exception handlers', severity: 'P1' },
    ];

    for (const { pattern, name, severity } of crashPatterns) {
      const { stdout } = await execAsync(
        `grep -r "${pattern}" ${repoPath} --include="*.ts" --include="*.js" | head -5 || true`,
        { timeout: 30000 }
      );

      if (stdout && stdout.trim().length > 0) {
        stabilityScore -= severity === 'P1' ? 20 : 10;
        findings.push({
          id: `stability-${name.toLowerCase().replace(/\s+/g, '-')}`,
          category: 'reliability',
          severity: severity as 'P0' | 'P1' | 'P2' | 'P3',
          title: `${name} detected`,
          description: `Found ${name} in codebase which may indicate stability issues`,
          evidence: [createEvidence(stdout.split('\n')[0], 'grep')],
          remediation: createRemediation(`Review and handle ${name} appropriately`),
          verified: true,
          createdAt: new Date(),
        });
      }
    }

    logger.info({ stabilityScore, findingsCount: findings.length }, 'Stability assessment completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage }, 'Stability assessment failed');
  }

  return {
    findings,
    stabilityScore,
    result: stabilityScore >= 70 ? 'PASSED' : 'FAILED'
  };
}

/**
 * Robustness Assessment Activity (ISO 25010 §4.7)
 * Checks error handling, edge case coverage, null safety
 */
export async function assessRobustness(
  repoPath: string
): Promise<{ findings: Finding[]; robustnessScore: number; result: string }> {
  logger.info({ repoPath }, 'Assessing robustness');

  const findings: Finding[] = [];
  let robustnessScore = 100;

  try {
    // Check for error handling patterns
    const { stdout: tryCatchCount } = await execAsync(
      String.raw`grep -r "try\s*{" ${repoPath} --include="*.ts" --include="*.js" | wc -l || true`,
      { timeout: 30000 }
    );

    const { stdout: catchCount } = await execAsync(
      String.raw`grep -r "catch\s*(" ${repoPath} --include="*.ts" --include="*.js" | wc -l || true`,
      { timeout: 30000 }
    );

    const tryCount = Number.parseInt(tryCatchCount.trim()) || 0;
    const catCount = Number.parseInt(catchCount.trim()) || 0;

    if (tryCount === 0 && catCount === 0) {
      robustnessScore -= 30;
      findings.push({
        id: 'robustness-001',
        category: 'reliability',
        severity: 'P1',
        title: 'No error handling detected',
        description: 'No try-catch blocks found in codebase',
        evidence: [createEvidence('Grep search returned zero count', 'grep')],
        remediation: createRemediation('Add error handling for critical operations'),
        verified: true,
        createdAt: new Date(),
      });
    }

    // Check for null safety
    const { stdout: nullChecks } = await execAsync(
      String.raw`grep -r "=== null\|=== undefined\|!= null\|!= undefined" ${repoPath} --include="*.ts" --include="*.js" | wc -l || true`,
      { timeout: 30000 }
    );

    const nullCheckCount = Number.parseInt(nullChecks.trim()) || 0;

    if (nullCheckCount < 5) {
      robustnessScore -= 15;
      findings.push({
        id: 'robustness-002',
        category: 'reliability',
        severity: 'P2',
        title: 'Low null safety coverage',
        description: `Only ${nullCheckCount} null checks found in codebase`,
        evidence: [createEvidence(`Null checks: ${nullCheckCount}`, 'grep')],
        remediation: createRemediation('Add null/undefined checks for safer code'),
        verified: true,
        createdAt: new Date(),
      });
    }

    logger.info({ robustnessScore, findingsCount: findings.length }, 'Robustness assessment completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage }, 'Robustness assessment failed');
  }

  return {
    findings,
    robustnessScore,
    result: robustnessScore >= 70 ? 'PASSED' : 'NEEDS_ATTENTION'
  };
}

/**
 * Resilience Assessment Activity (ISO 25010 §4.8)
 * Checks retry logic, circuit breakers, graceful degradation
 */
export async function assessResilience(
  repoPath: string
): Promise<{ findings: Finding[]; resilienceScore: number; result: string }> {
  logger.info({ repoPath }, 'Assessing resilience');

  const findings: Finding[] = [];
  let resilienceScore = 100;

  try {
    // Check for resilience patterns
    const resiliencePatterns = [
      { pattern: 'retry|backoff|exponential', name: 'Retry logic' },
      { pattern: 'circuit.?breaker|breaker', name: 'Circuit breaker' },
      { pattern: 'health.?check|readiness|liveness', name: 'Health checks' },
      { pattern: 'fallback|graceful|degradation', name: 'Graceful degradation' },
    ];

    for (const { pattern, name } of resiliencePatterns) {
      const { stdout } = await execAsync(
        `grep -ri "${pattern}" ${repoPath} --include="*.ts" --include="*.js" --include="*.yaml" --include="*.yml" | head -5 || true`,
        { timeout: 30000 }
      );

      if (!stdout || stdout.trim().length === 0) {
        resilienceScore -= 20;
        findings.push({
          id: `resilience-${name.toLowerCase().replace(/\s+/g, '-')}`,
          category: 'reliability',
          severity: 'P1',
          title: `Missing ${name.toLowerCase()}`,
          description: `No ${name.toLowerCase()} patterns detected`,
          evidence: [createEvidence('Grep search returned no results', 'grep')],
          remediation: createRemediation(`Implement ${name.toLowerCase()} for better resilience`),
          verified: true,
          createdAt: new Date(),
        });
      }
    }

    logger.info({ resilienceScore, findingsCount: findings.length }, 'Resilience assessment completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage }, 'Resilience assessment failed');
  }

  return {
    findings,
    resilienceScore,
    result: resilienceScore >= 70 ? 'PASSED' : 'NEEDS_ATTENTION'
  };
}

/**
 * Exploitability Assessment Activity (ISO 25010 §2.6)
 * Calculates CVSS scores and exploitability metrics for vulnerabilities
 */
export async function assessExploitability(
  vulnerabilities: Array<{ cve: string; severity: string; description: string }>
): Promise<{ findings: Finding[]; exploitabilityScores: Array<{ cve: string; score: number }>; result: string }> {
  logger.info({ vulnerabilityCount: vulnerabilities.length }, 'Assessing exploitability');

  const findings: Finding[] = [];
  const exploitabilityScores: Array<{ cve: string; score: number }> = [];
  let highExploitability = 0;

  try {
    for (const vuln of vulnerabilities) {
      // Simplified CVSS-like scoring
      let score = 0;
      switch (vuln.severity.toUpperCase()) {
        case 'CRITICAL':
          score = 9.0;
          break;
        case 'HIGH':
          score = 7.5;
          break;
        case 'MEDIUM':
          score = 5.0;
          break;
        case 'LOW':
          score = 2.5;
          break;
        default:
          score = 5.0;
      }

      exploitabilityScores.push({ cve: vuln.cve, score });

      if (score >= 7.0) {
        highExploitability++;
        findings.push({
          id: `exploitability-${vuln.cve}`,
          category: 'security-dependencies',
          severity: 'P1',
          title: `High exploitability: ${vuln.cve}`,
          description: `${vuln.cve} has high exploitability score: ${score}`,
          evidence: [createEvidence(`CVSS score: ${score}`, 'cvss')],
          remediation: createRemediation('Patch immediately or implement mitigations', 'immediate', 'hours'),
          verified: true,
          createdAt: new Date(),
        });
      }
    }

    logger.info({ highExploitability, findingsCount: findings.length }, 'Exploitability assessment completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage }, 'Exploitability assessment failed');
  }

  return {
    findings,
    exploitabilityScores,
    result: highExploitability === 0 ? 'PASSED' : 'NEEDS_ATTENTION'
  };
}

/**
 * Code Readability Assessment Activity (ISO 25010 §13.5)
 * Checks code complexity, naming conventions, and documentation
 */
export async function measureReadability(
  repoPath: string
): Promise<{ findings: Finding[]; metrics: { avgComplexity: number; avgLinesPerFunction: number }; result: string }> {
  logger.info({ repoPath }, 'Measuring code readability');

  const findings: Finding[] = [];
  const metrics = { avgComplexity: 0, avgLinesPerFunction: 0 };

  try {
    // Check for ESLint configuration
    const eslintConfigPath = path.join(repoPath, '.eslintrc.js');
    if (!existsSync(eslintConfigPath)) {
      findings.push({
        id: 'readability-001',
        category: 'security-code-review',
        severity: 'P2',
        title: 'ESLint not configured',
        description: 'ESLint configuration file not found',
        evidence: [createEvidence(`Missing ${eslintConfigPath}`, 'file-check')],
        remediation: createRemediation('Add ESLint configuration with complexity rules'),
        verified: true,
        createdAt: new Date(),
      });
    }

    // Check for large files (indicator of poor readability)
    const { stdout: largeFiles } = await execAsync(
      `find ${repoPath} -name "*.ts" -o -name "*.js" | xargs wc -l | sort -rn | head -10 || true`,
      { timeout: 30000 }
    );

    const lines = largeFiles.trim().split('\n').filter(line => line.includes('total') === false);
    for (const line of lines.slice(0, 5)) {
      const match = /^(\d+)\s+(\S.*)$/.exec(line);
      if (match) {
        const [, lineCount, filePath] = match;
        if (Number.parseInt(lineCount) > 500) {
          findings.push({
            id: `readability-002-${path.basename(filePath)}`,
            category: 'security-code-review',
            severity: 'P2',
            title: 'Large file detected',
            description: `File ${path.basename(filePath)} has ${lineCount} lines`,
            evidence: [createEvidence(line, 'find')],
            remediation: createRemediation('Consider splitting large files into smaller modules'),
            verified: true,
            createdAt: new Date(),
          });
        }
      }
    }

    logger.info({ findingsCount: findings.length }, 'Readability measurement completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error({ error: errorMessage }, 'Readability measurement failed');
  }

  return {
    findings,
    metrics,
    result: findings.filter(f => f.severity === 'P0' || f.severity === 'P1').length === 0 ? 'PASSED' : 'NEEDS_ATTENTION'
  };
}
// ==================== RUN LIFECYCLE ACTIVITIES ====================

function evidenceRoot(): string {
  const configured = process.env.TESSERA_EVIDENCE_ROOT;
  return configured !== undefined && configured.length > 0
    ? configured
    : path.join(os.homedir(), '.local', 'share', 'tessera', 'evidence');
}

function signingKeyPath(): string {
  const configured = process.env.TESSERA_SIGNING_KEY;
  return configured !== undefined && configured.length > 0
    ? configured
    : path.join(os.homedir(), '.config', 'tessera', 'signing', 'ed25519.pem');
}

function frameworkVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(path.resolve(__dirname, '..', '..', 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

function currentExecution(): { workflowId: string; runId: string; attempt: number } {
  const info = Context.current().info;
  if (info.workflowExecution === undefined) {
    throw ApplicationFailure.create({ message: 'run lifecycle activities require a workflow execution', type: 'InvalidRunError', nonRetryable: true });
  }
  return { workflowId: info.workflowExecution.workflowId, runId: info.workflowExecution.runId, attempt: info.attempt };
}

function toApplicationFailure(error: unknown): unknown {
  if (error instanceof lifecycle.LifecycleInputError) {
    return ApplicationFailure.create({
      message: error.message,
      type: error.code === 'invalid-repo-url' ? 'InvalidRepoError' : 'InvalidRunError',
      nonRetryable: true,
    });
  }
  if (error instanceof lifecycle.SourceFetchFailure) {
    return ApplicationFailure.create({
      message: error.message,
      type: error.kind === 'network' ? 'SourceNetworkError' : 'SourceUnavailableError',
      nonRetryable: !error.retryable,
      details: [{ evidenceRecordIds: [...error.evidenceRecordIds] }],
    });
  }
  return error;
}

export async function initAuditRun(): Promise<AuditRun> {
  const workflowExecution = currentExecution();
  try {
    const run = await lifecycle.initAuditRun({
      workflowId: workflowExecution.workflowId,
      temporalRunId: workflowExecution.runId,
      tmpRoot: os.tmpdir(),
    });
    logger.info({ runId: run.runId }, 'Audit run initialized');
    return run;
  } catch (error) {
    logger.error({ runId: workflowExecution.runId, error: error instanceof Error ? error.message : String(error) }, 'Audit run initialization failed');
    throw toApplicationFailure(error);
  }
}

export async function fetchSource(run: AuditRun, repoUrl: string): Promise<FetchedSource> {
  const workflowExecution = currentExecution();
  const { attempt } = workflowExecution;
  try {
    const source = await lifecycle.fetchSource(run, repoUrl, {
      runner: defaultProcessRunner,
      tmpRoot: os.tmpdir(),
      store: createEvidenceStore(evidenceRoot(), run.runId),
      clock: () => new Date(),
      frameworkVersion: frameworkVersion(),
      attempt,
    });
    const steering = steeringCounts(source.overrideAttempts);
    logger.info({ runId: run.runId, revision: source.revision, controlFiles: steering.controlFiles, inlineMarkers: steering.inlineMarkers }, 'Source fetched');
    return source;
  } catch (error) {
    logger.warn({ runId: run.runId, error: error instanceof Error ? error.message : String(error) }, 'Source fetch failed');
    throw toApplicationFailure(error);
  }
}

export async function cleanupRun(run: AuditRun): Promise<void> {
  await lifecycle.cleanupRun(run, os.tmpdir());
  logger.info({ runId: run.runId }, 'Audit run work dir removed');
}

function workerScanActivities(): ScanActivities {
  return createScanActivities({
    runner: defaultProcessRunner,
    clock: () => new Date(),
    evidenceRoot: evidenceRoot(),
    tmpRoot: os.tmpdir(),
    frameworkVersion: frameworkVersion(),
    workerEnv: process.env,
    configDir: path.resolve(__dirname, '..', '..', 'config', 'scanners'),
    signingKeyPath: signingKeyPath(),
    requireSignature: process.env.TESSERA_REQUIRE_SIGNATURE === '1',
  });
}

function scanActivity(name: Exclude<keyof ScanActivities, 'sealEvidence' | 'signEvidence'>): ScanActivity {
  return (run, source, repoUrl) => workerScanActivities()[name](run, source, repoUrl);
}

export async function sealEvidence(input: SealEvidenceActivityInput): Promise<SealEvidenceActivityResult> {
  const result = await workerScanActivities().sealEvidence(input);
  logger.info({ runId: input?.run?.runId, rootHash: result.rootHash, recordCount: result.recordCount }, 'Evidence bundle sealed');
  return result;
}

export async function signEvidence(input: SignEvidenceActivityInput): Promise<SignEvidenceResult> {
  const result = await workerScanActivities().signEvidence(input);
  const log = { runId: input?.run?.runId, signed: result.signed, required: result.required, keyId: result.keyId ?? null, level: result.level, detail: result.detail ?? null };
  if (result.level === 1 || !result.required) logger.info(log, 'Evidence signature step finished');
  else logger.warn(log, 'Evidence bundle has no valid signature');
  return result;
}

export const runGitleaks: ScanActivity = scanActivity('runGitleaks');
export const runSemgrep: ScanActivity = scanActivity('runSemgrep');
export const runNpmAudit: ScanActivity = scanActivity('runNpmAudit');
export const runLicenseCheck: ScanActivity = scanActivity('runLicenseCheck');
