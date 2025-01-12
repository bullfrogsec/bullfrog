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

export async function waitForStringInFile({
  filePath,
  str,
  timeoutMs,
}: {
  filePath: string;
  str: string;
  timeoutMs: number;
}) {
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    let content = "";
    try {
      content = await fs.readFile(filePath, { encoding: "utf-8" });
      // eslint-disable-next-line no-empty
    } catch {}

    if (content.includes(str)) {
      return;
    }

    await setTimeout(500);
  }

  throw new Error(`Couldn't find ${str} in file ${filePath}`);
}

export async function getFileTimestamp(filePath: string): Promise<number> {
  try {
    const stats = await fs.stat(filePath);
    return stats.mtime.getTime();
  } catch (err) {
    core.debug(`Error getting ${filePath} file timestamp: ${err}`);
    return 0;
  }
}
