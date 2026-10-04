// Contract: explicit activity registration (FR-014, SC-007)
// Target modules: src/activities/registry.ts, src/worker.ts, src/workflows/index.ts (proxy type only)

export const WORKFLOW_ACTIVITY_NAMES = [
  'initAuditRun',
  'checkIsolation',
  'fetchSource',
  'detectTechStack',
  'generateScopeDocument',
  'runNpmAudit',
  'runGitleaks',
  'runSemgrep',
  'runLicenseCheck',
  'reviewCriticalPaths',
  'mapToCompliance',
  'crossValidate',
  'generateReport',
  'teardownEnvironment',
  'sealEvidence',
  'signEvidence',
] as const;

export type WorkflowActivityName = (typeof WORKFLOW_ACTIVITY_NAMES)[number];

// Every export of src/activities/index.ts that is not in WORKFLOW_ACTIVITY_NAMES and that runs a command,
// reads the source, or calls the network. The test asserts none of these is a key of workflowActivities.
export const LEGACY_ACTIVITY_NAMES = [
  'checkToolRequirements',
  'runLighthouse',
  'runAxeAccessibility',
  'runSqlInjectionCheck',
  'checkReliability',
  'checkObservability',
  'checkCicd',
  'waitForHumanApproval',
  'checkCodeQuality',
  'checkDocumentation',
  'checkPrivacy',
  'checkFunctionalRequirements',
  'checkBlindSpots',
  'measureThroughput',
  'assessDurability',
  'assessStability',
  'assessRobustness',
  // cleanupRun (004) is replaced by teardownEnvironment and is not registered either
  // the remaining legacy exports are listed by the implementation task from the actual module (tail of index.ts)
] as const;

// src/activities/registry.ts
//   export const workflowActivities: Readonly<Record<WorkflowActivityName, (...args: never[]) => Promise<unknown>>>
//   export type WorkflowActivities = typeof workflowActivities
// The object is frozen. src/workflows/index.ts uses proxyActivities<WorkflowActivities>(…).

// src/worker.ts
export interface WorkerOptionsShape {
  taskQueue: 'audit';
  activities: unknown;                 // must be the workflowActivities object itself (identity check in the test)
  workflowsPath: string;
  maxConcurrentActivityTaskExecutions: 4;
  maxConcurrentWorkflowTaskExecutions: 10;
}
export type BuildWorkerOptions = () => WorkerOptionsShape;
// At start the worker logs { registeredActivities: WORKFLOW_ACTIVITY_NAMES, isolation: <check summary> }.
