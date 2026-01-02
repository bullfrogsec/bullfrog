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
