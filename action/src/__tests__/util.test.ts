import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { waitForFile, getDate } from "../util";
import * as core from "@actions/core";
import fs from "node:fs/promises";

vi.mock("@actions/core");
vi.mock("node:fs/promises");

describe("util", () => {
  describe("waitForFile", () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("should return true when file is immediately available", async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      const result = await waitForFile("/test/file.txt");

      expect(result).toBe(true);
      expect(fs.access).toHaveBeenCalledWith("/test/file.txt");
      expect(core.debug).toHaveBeenCalledWith(
        "File /test/file.txt is available!",
      );
    });

    it("should return true when file becomes available within timeout", async () => {
      let callCount = 0;
      vi.mocked(fs.access).mockImplementation(() => {
        callCount++;
        if (callCount <= 2) {
          return Promise.reject(new Error("ENOENT"));
        }
        return Promise.resolve(undefined);
      });

      const result = await waitForFile("/test/file.txt", 5000, 100);

      expect(result).toBe(true);
      expect(fs.access).toHaveBeenCalledTimes(3);
    });

    it("should return false when file is not available after timeout", async () => {
      vi.mocked(fs.access).mockRejectedValue(new Error("ENOENT"));

      const result = await waitForFile("/test/file.txt", 500, 100);

      expect(result).toBe(false);
      expect(core.debug).toHaveBeenCalledWith(
        "Timeout: File /test/file.txt is not available.",
      );
    });

    it("should use default timeout and interval values", async () => {
      vi.mocked(fs.access).mockResolvedValue(undefined);

      await waitForFile("/test/file.txt");

      expect(fs.access).toHaveBeenCalled();
    });

    it("should respect custom timeout and interval", async () => {
      vi.mocked(fs.access).mockRejectedValue(new Error("ENOENT"));

      const startTime = Date.now();
      await waitForFile("/test/file.txt", 300, 50);
      const elapsed = Date.now() - startTime;

      expect(elapsed).toBeGreaterThanOrEqual(300);
      expect(elapsed).toBeLessThan(500);
    });
  });

  describe("getDate", () => {
    it("should convert nanoseconds timestamp (> 1e15) to Date", () => {
      const nanoseconds = 1609459200000000000; // 2021-01-01 00:00:00 in ns
      const date = getDate(nanoseconds);

      expect(date).toBeInstanceOf(Date);
      expect(date.getTime()).toBe(1609459200000);
    });

    it("should convert milliseconds timestamp (> 1e12, < 1e15) to Date", () => {
      const milliseconds = 1609459200000; // 2021-01-01 00:00:00 in ms
      const date = getDate(milliseconds);

      expect(date).toBeInstanceOf(Date);
      expect(date.getTime()).toBe(milliseconds);
    });

    it("should convert seconds timestamp (< 1e12) to Date", () => {
      const seconds = 1609459200; // 2021-01-01 00:00:00 in seconds
      const date = getDate(seconds);

      expect(date).toBeInstanceOf(Date);
      expect(date.getTime()).toBe(1609459200000);
    });

    it("should handle edge case at nanoseconds boundary", () => {
      const timestamp = 1e15 + 1;
      const date = getDate(timestamp);

      expect(date.getTime()).toBe(Math.floor(timestamp / 1e6));
    });

    it("should handle edge case at milliseconds boundary", () => {
      const timestamp = 1e12 + 1;
      const date = getDate(timestamp);

      expect(date.getTime()).toBe(timestamp);
    });

    it("should handle zero timestamp", () => {
      const date = getDate(0);

      expect(date).toBeInstanceOf(Date);
      expect(date.getTime()).toBe(0);
    });

    it("should handle small timestamp values (seconds)", () => {
      const timestamp = 1000; // 1000 seconds after epoch
      const date = getDate(timestamp);

      expect(date.getTime()).toBe(1000000);
    });
  });
});
