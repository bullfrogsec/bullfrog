import { describe, it, expect } from "vitest";
import {
  getHumanFriendlyReason,
  filterDNSNoise,
  deduplicateByDomain,
  deduplicateByDomainAndIP,
  type Connection,
} from "../post";

describe("post", () => {
  describe("getHumanFriendlyReason", () => {
    it("should map known reason codes to human-friendly descriptions", () => {
      expect(getHumanFriendlyReason("domain-allowed")).toBe("Domain allowed");
      expect(getHumanFriendlyReason("domain-not-allowed")).toBe(
        "Domain not allowed",
      );
      expect(getHumanFriendlyReason("dns-resolved")).toBe("DNS resolved");
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

  describe("deduplicateByDomain", () => {
    it("should deduplicate connections by domain", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "google.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
        },
      ];

      const result = deduplicateByDomain(connections);

      expect(result).toHaveLength(2);
      expect(result[0].domain).toBe("example.com");
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
      expect(result[1].domain).toBe("google.com");
    });

    it("should keep the first occurrence by timestamp", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
        },
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "domain-allowed",
        },
      ];

      const result = deduplicateByDomain(connections);

      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
    });

    it("should handle empty connections array", () => {
      const result = deduplicateByDomain([]);

      expect(result).toEqual([]);
    });

    it("should treat undefined domain as 'unknown'", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: undefined,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: undefined,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
        },
      ];

      const result = deduplicateByDomain(connections);

      expect(result).toHaveLength(1);
    });
  });

  describe("deduplicateByDomainAndIP", () => {
    it("should deduplicate connections by domain and IP combination", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "dns-resolved",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "dns-resolved",
        },
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          ip: "93.184.216.35",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "dns-resolved",
        },
      ];

      const result = deduplicateByDomainAndIP(connections);

      expect(result).toHaveLength(2);
      expect(result[0].ip).toBe("93.184.216.34");
      expect(result[1].ip).toBe("93.184.216.35");
    });

    it("should keep the first occurrence by timestamp", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:02Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "dns-resolved",
        },
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "example.com",
          ip: "93.184.216.34",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "dns-resolved",
        },
      ];

      const result = deduplicateByDomainAndIP(connections);

      expect(result).toHaveLength(1);
      expect(result[0].timestamp).toEqual(new Date("2024-01-01T00:00:00Z"));
    });

    it("should handle empty connections array", () => {
      const result = deduplicateByDomainAndIP([]);

      expect(result).toEqual([]);
    });

    it("should treat undefined domain and IP as 'unknown'", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: undefined,
          ip: undefined,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: undefined,
          ip: undefined,
          blocked: false,
          authorized: true,
          protocol: "TCP",
          reason: "ip-allowed",
        },
      ];

      const result = deduplicateByDomainAndIP(connections);

      expect(result).toHaveLength(1);
    });

    it("should differentiate between different IPs for the same domain", () => {
      const connections: Connection[] = [
        {
          timestamp: new Date("2024-01-01T00:00:00Z"),
          domain: "google.com",
          ip: "172.217.0.1",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "dns-resolved",
        },
        {
          timestamp: new Date("2024-01-01T00:00:01Z"),
          domain: "google.com",
          ip: "172.217.0.2",
          blocked: false,
          authorized: true,
          protocol: "DNS",
          reason: "dns-resolved",
        },
      ];

      const result = deduplicateByDomainAndIP(connections);

      expect(result).toHaveLength(2);
    });
  });

  describe("filterDNSNoise", () => {
    describe("Scenario 1: Non-DNS connection with ip-allowed exists", () => {
      it("should exclude dns-resolved and domain-allowed when actual connection exists", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "example.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
          {
            timestamp: new Date("2024-01-01T00:00:01Z"),
            domain: "example.com",
            ip: "93.184.216.34",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "dns-resolved",
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
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(1);
        expect(result[0].protocol).toBe("TCP");
        expect(result[0].reason).toBe("ip-allowed");
      });

      it("should keep non-DNS connections and other reasons", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "example.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
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
          },
          {
            timestamp: new Date("2024-01-01T00:00:02Z"),
            domain: "example.com",
            ip: "93.184.216.34",
            port: 80,
            blocked: false,
            authorized: true,
            protocol: "TCP",
            reason: "ip-allowed",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(2);
        expect(result.every((c) => c.protocol === "TCP")).toBe(true);
      });
    });

    describe("Scenario 2: Only dns-resolved connections", () => {
      it("should deduplicate by domain and IP", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "google.com",
            ip: "172.217.0.1",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "dns-resolved",
          },
          {
            timestamp: new Date("2024-01-01T00:00:01Z"),
            domain: "google.com",
            ip: "172.217.0.1",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "dns-resolved",
          },
          {
            timestamp: new Date("2024-01-01T00:00:02Z"),
            domain: "google.com",
            ip: "172.217.0.2",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "dns-resolved",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(2);
        expect(result[0].ip).toBe("172.217.0.1");
        expect(result[1].ip).toBe("172.217.0.2");
      });
    });

    describe("Scenario 3: Only domain-allowed connections", () => {
      it("should deduplicate by domain", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "example.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
          {
            timestamp: new Date("2024-01-01T00:00:01Z"),
            domain: "example.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
          {
            timestamp: new Date("2024-01-01T00:00:02Z"),
            domain: "example.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(1);
        expect(result[0].domain).toBe("example.com");
      });
    });

    describe("Scenario 4: Blocked connections", () => {
      it("should deduplicate blocked entries by domain", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "blocked.com",
            blocked: true,
            authorized: false,
            protocol: "TCP",
            reason: "domain-not-allowed",
          },
          {
            timestamp: new Date("2024-01-01T00:00:01Z"),
            domain: "blocked.com",
            blocked: true,
            authorized: false,
            protocol: "TCP",
            reason: "domain-not-allowed",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(1);
        expect(result[0].domain).toBe("blocked.com");
      });
    });

    describe("Scenario 5: Mixed scenarios", () => {
      it("should handle multiple domains with different scenarios", () => {
        const connections: Connection[] = [
          // example.com: has actual connection
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "example.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
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
          },
          // google.com: only DNS queries
          {
            timestamp: new Date("2024-01-01T00:00:02Z"),
            domain: "google.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
          {
            timestamp: new Date("2024-01-01T00:00:03Z"),
            domain: "google.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
          // blocked.com: blocked
          {
            timestamp: new Date("2024-01-01T00:00:04Z"),
            domain: "blocked.com",
            blocked: true,
            authorized: false,
            protocol: "TCP",
            reason: "domain-not-allowed",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(3);

        // example.com should only have the TCP connection
        const exampleConns = result.filter((c) => c.domain === "example.com");
        expect(exampleConns).toHaveLength(1);
        expect(exampleConns[0].protocol).toBe("TCP");

        // google.com should have one deduplicated DNS query
        const googleConns = result.filter((c) => c.domain === "google.com");
        expect(googleConns).toHaveLength(1);
        expect(googleConns[0].reason).toBe("domain-allowed");

        // blocked.com should have one entry
        const blockedConns = result.filter((c) => c.domain === "blocked.com");
        expect(blockedConns).toHaveLength(1);
      });
    });

    describe("Edge cases", () => {
      it("should handle empty connections array", () => {
        const result = filterDNSNoise([]);

        expect(result).toEqual([]);
      });

      it("should handle connections with unknown domain", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: undefined,
            ip: "8.8.8.8",
            blocked: true,
            authorized: false,
            protocol: "DNS",
            reason: "untrusted-dns-server",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(1);
      });

      it("should deduplicate untrusted DNS server connections", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "example.com",
            ip: "8.8.8.8",
            blocked: true,
            authorized: false,
            protocol: "DNS",
            reason: "untrusted-dns-server",
          },
          {
            timestamp: new Date("2024-01-01T00:00:01Z"),
            domain: "example.com",
            ip: "8.8.8.8",
            blocked: true,
            authorized: false,
            protocol: "DNS",
            reason: "untrusted-dns-server",
          },
        ];

        const result = filterDNSNoise(connections);

        // Blocked connections are deduplicated by domain
        expect(result).toHaveLength(1);
        expect(result[0].reason).toBe("untrusted-dns-server");
      });

      it("should preserve all non-DNS, non-ip-allowed connections", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "example.com",
            ip: "93.184.216.34",
            port: 443,
            blocked: true,
            authorized: false,
            protocol: "TCP",
            reason: "ip-not-allowed",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(1);
        expect(result[0].reason).toBe("ip-not-allowed");
      });
    });

    describe("DNS vs non-DNS protocol detection", () => {
      it("should only filter DNS protocol connections", () => {
        const connections: Connection[] = [
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "example.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
          {
            timestamp: new Date("2024-01-01T00:00:01Z"),
            domain: "example.com",
            ip: "93.184.216.34",
            port: 443,
            blocked: false,
            authorized: true,
            protocol: "UDP",
            reason: "ip-allowed",
          },
        ];

        const result = filterDNSNoise(connections);

        // Should exclude DNS domain-allowed since there's a non-DNS ip-allowed
        expect(result).toHaveLength(1);
        expect(result[0].protocol).toBe("UDP");
      });
    });

    describe("Real-world scenario: HTTP connection after DNS lookup", () => {
      it("should show only the HTTP connection, hiding DNS noise", () => {
        const connections: Connection[] = [
          // DNS query
          {
            timestamp: new Date("2024-01-01T00:00:00Z"),
            domain: "api.github.com",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "domain-allowed",
          },
          // DNS response
          {
            timestamp: new Date("2024-01-01T00:00:01Z"),
            domain: "api.github.com",
            ip: "140.82.121.6",
            blocked: false,
            authorized: true,
            protocol: "DNS",
            reason: "dns-resolved",
          },
          // Actual HTTPS connection
          {
            timestamp: new Date("2024-01-01T00:00:02Z"),
            domain: "api.github.com",
            ip: "140.82.121.6",
            port: 443,
            blocked: false,
            authorized: true,
            protocol: "TCP",
            reason: "ip-allowed",
          },
        ];

        const result = filterDNSNoise(connections);

        expect(result).toHaveLength(1);
        expect(result[0].protocol).toBe("TCP");
        expect(result[0].port).toBe(443);
        expect(result[0].domain).toBe("api.github.com");
      });
    });
  });
});
