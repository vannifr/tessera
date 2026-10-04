module.exports = {
  default: {
    paths: ['specs/004-reliable-scan-core/tests/features/**/*.feature'],
    require: ['specs/004-reliable-scan-core/tests/step_definitions/**/*.ts'],
    requireModule: ['ts-node/register'],
    format: ['progress', 'html:coverage/cucumber-report.html'],
    publishQuiet: true,
  },
  legacy: {
    paths: ['specs/00[123]-*/tests/features/**/*.feature'],
    require: ['tests/step_definitions/**/*.ts', 'specs/00[123]-*/tests/step_definitions/**/*.ts'],
    requireModule: ['ts-node/register'],
    format: ['progress'],
    publishQuiet: true,
  },
  '005': {
    paths: ['specs/005-isolated-execution/tests/features/**/*.feature'],
    require: [
      'specs/005-isolated-execution/tests/support/**/*.ts',
      'specs/005-isolated-execution/tests/step_definitions/**/*.ts',
    ],
    requireModule: ['ts-node/register'],
    format: ['progress'],
    publishQuiet: true,
  },
};
