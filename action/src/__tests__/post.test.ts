import { describe, it, expect } from "vitest";
import {
  getHumanFriendlyReason,
  filterConnectionsNoise,
  type Connection,
} from "../post";

describe("post", () => {
  describe("getHumanFriendlyReason", () => {
    it("should map known reason codes to human-friendly descriptions", () => {
      expect(getHumanFriendlyReason("domain-allowed")).toBe("Domain allowed");
      expect(getHumanFriendlyReason("domain-not-allowed")).toBe(
        "Domain not allowed",
      );
      expect(getHumanFriendlyReason("ip-allowed")).toBe("IP allowed");
      expect(getHumanFriendlyReason("ip-not-allowed")).toBe("IP not allowed");
      expect(getHumanFriendlyReason("untrusted-dns-server")).toBe(
        "Untrusted DNS server",
      );
      expect(getHumanFriendlyReason("no-network-layer")).toBe(
        "No network layer",
      );
      expect(getHumanFriendlyReason("unknown-network-layer")).toBe(
        "Unknown network layer",
      );
    });

    it("should return the original code for unknown reason codes", () => {
      expect(getHumanFriendlyReason("unknown-reason")).toBe("unknown-reason");
      expect(getHumanFriendlyReason("custom-code")).toBe("custom-code");
      expect(getHumanFriendlyReason("")).toBe("");
    });
  });

  describe("filterConnectionsNoise", () => {
    it("should deduplicate by domain+ip+process+docker - same everything", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep only the first one (earliest timestamp)
      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
    });

    it("should NOT deduplicate when process is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "wget",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].process).toBe("curl");
      expect(result[1].process).toBe("wget");
    });

    it("should NOT deduplicate when docker container is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web1",
          },
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web2",
          },
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].docker?.containerName).toBe("web1");
      expect(result[1].docker?.containerName).toBe("web2");
    });

    it("should NOT deduplicate when IP is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.35",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].ip).toBe("93.184.216.34");
      expect(result[1].ip).toBe("93.184.216.35");
    });

    it("should NOT deduplicate when domain is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "google.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].domain).toBe("example.com");
      expect(result[1].domain).toBe("google.com");
    });

    it("should keep DNS connections even when TCP connections exist for same domain", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "api.github.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "api.github.com",
          ip: "140.82.121.6",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep both DNS and TCP connections
      expect(result).toHaveLength(2);
      expect(result[0].protocol).toBe("DNS");
      expect(result[1].protocol).toBe("TCP");
    });

    it("should deduplicate multiple DNS queries to same domain by same process", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep only the first occurrence (DNS has no IP, so dedup by domain+process+docker)
      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
    });

    it("should NOT deduplicate DNS queries from different processes", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "wget",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].process).toBe("curl");
      expect(result[1].process).toBe("wget");
    });

    it("should handle undefined process/exePath/commandLine consistently", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: undefined,
          exePath: undefined,
          commandLine: undefined,
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: undefined,
          exePath: undefined,
          commandLine: undefined,
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should deduplicate since all fields are the same
      expect(result).toHaveLength(1);
    });

    it("should handle undefined docker consistently", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: undefined,
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: undefined,
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should deduplicate since all fields are the same
      expect(result).toHaveLength(1);
    });

    it("should handle empty connections array", () => {
      const result = filterConnectionsNoise([]);
      expect(result).toEqual([]);
    });

    it("should handle mixed scenario with multiple processes and containers", () => {
      const connections: Connection[] = [
        // curl to example.com
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        // wget to example.com
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          process: "wget",
        },
        {
          timestamp: new Date("2024-01-01T00:00:03Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "wget",
        },
        // docker container web1 to example.com
        {
          timestamp: new Date("2024-01-01T00:00:04Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web1",
          },
        },
        {
          timestamp: new Date("2024-01-01T00:00:05Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          port: 443,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          docker: {
            containerImage: "nginx",
            containerName: "web1",
          },
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should have 6 entries: DNS+TCP for curl, DNS+TCP for wget, DNS+TCP for web1
      expect(result).toHaveLength(6);

      const curlConns = result.filter((c) => c.process === "curl");
      expect(curlConns).toHaveLength(2);

      const wgetConns = result.filter((c) => c.process === "wget");
      expect(wgetConns).toHaveLength(2);

      const dockerConns = result.filter(
        (c) => c.docker?.containerName === "web1",
      );
      expect(dockerConns).toHaveLength(2);
    });

    it("should NOT deduplicate when exePath is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "python",
          exePath: "/usr/bin/python3",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "python",
          exePath: "/usr/local/bin/python3",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].exePath).toBe("/usr/bin/python3");
      expect(result[1].exePath).toBe("/usr/local/bin/python3");
    });

    it("should NOT deduplicate when commandLine is different", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
          commandLine: "curl https://example.com",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
          commandLine: "curl https://example.com/api",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].commandLine).toBe("curl https://example.com");
      expect(result[1].commandLine).toBe("curl https://example.com/api");
    });

    it("should deduplicate multiple blocked connections to same domain by same process", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Should keep only the first blocked connection
      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
      expect(result[0].blocked).toBe(true);
    });

    it("should NOT deduplicate blocked connections from different processes", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "malicious.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "domain-not-allowed",
          process: "wget",
        },
      ];

      const result = filterConnectionsNoise(connections);

      expect(result).toHaveLength(2);
      expect(result[0].process).toBe("curl");
      expect(result[1].process).toBe("wget");
    });

    it("should keep both allowed and blocked connections to same domain", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "1.2.3.4",
          blocked: true,
          authorized: false,
          protocol: "TCP",
          reason: "ip-not-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Different IPs, so should keep both
      expect(result).toHaveLength(2);
      expect(result[0].blocked).toBe(false);
      expect(result[1].blocked).toBe(true);
    });

    it("should deduplicate blocked DNS queries", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "malicious.com",
          blocked: true,
          authorized: false,
          protocol: "DNS",
          reason: "domain-not-allowed",
          process: "curl",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "malicious.com",
          blocked: true,
          authorized: false,
          protocol: "DNS",
          reason: "domain-not-allowed",
          process: "curl",
        },
      ];

      const result = filterConnectionsNoise(connections);

      // Same domain, no IP (DNS), same process -> deduplicate
      expect(result).toHaveLength(1);
      expect(result[0].protocol).toBe("DNS");
    });
  });
});
