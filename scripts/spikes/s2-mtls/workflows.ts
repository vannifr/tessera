import { proxyActivities } from '@temporalio/workflow';

const { echo } = proxyActivities<{ echo(s: string): Promise<string> }>({ startToCloseTimeout: '10 seconds' });

export async function s2Spike(input: string): Promise<string> {
  return await echo(input);
}
