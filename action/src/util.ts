import * as core from "@actions/core";
import fs from "node:fs/promises";
import { setTimeout } from "node:timers/promises";

export async function waitForFile(
  filePath: string,
  timeout = 15000,
  interval = 500,
) {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    try {
      await fs.access(filePath);
      core.debug(`File ${filePath} is available!`);
      return true;
    } catch {
      // File is not available yet
      await setTimeout(interval);
    }
  }

  core.debug(`Timeout: File ${filePath} is not available.`);
  return false;
}

export interface GitHubContext {
  workflowRunId: string;
  runAttempt: number;
  jobName?: string;
  organization: string;
  repo: string;
  workflowPath?: string;
}

export function getGitHubContext(): GitHubContext {
  const repo = process.env.GITHUB_REPOSITORY || "";
  const [organization] = repo.split("/");
  const workflowRunId = process.env.GITHUB_RUN_ID || "";
  const runAttempt = parseInt(process.env.GITHUB_RUN_ATTEMPT ?? "1");
  const jobName = process.env.GITHUB_JOB || undefined;

  if (!organization || !repo || !workflowRunId) {
    throw new Error(
      "Missing GitHub context: GITHUB_REPOSITORY or GITHUB_RUN_ID not set",
    );
  }

  return {
    workflowRunId,
    runAttempt,
    jobName,
    organization,
    repo,
    workflowPath: getWorkflowPath(repo),
  };
}

// GITHUB_WORKFLOW_REF is formatted as
// "owner/repo/.github/workflows/my-workflow.yml@refs/heads/my_branch" - this
// extracts just the workflow file path.
function getWorkflowPath(repo: string): string | undefined {
  const ref = process.env.GITHUB_WORKFLOW_REF;
  if (!ref) {
    return undefined;
  }

  const withoutRepo = ref.startsWith(`${repo}/`)
    ? ref.slice(repo.length + 1)
    : ref;
  const atIndex = withoutRepo.indexOf("@");
  return atIndex === -1 ? withoutRepo : withoutRepo.slice(0, atIndex);
}

// Determine if timestamp is in seconds, milliseconds, or nanoseconds
export function getDate(timestamp: number) {
  if (timestamp > 1e15) {
    // Likely nanoseconds, divide by 1e6
    return new Date(timestamp / 1e6);
  } else if (timestamp > 1e12) {
    // Likely milliseconds
    return new Date(timestamp);
  } else {
    // Likely seconds
    return new Date(timestamp * 1000);
  }
}
