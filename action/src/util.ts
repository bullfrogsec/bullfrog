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
    } catch (err) {
      // File is not available yet
      await setTimeout(interval);
    }
  }

  core.debug(`Timeout: File ${filePath} is not available.`);
  return false;
}
