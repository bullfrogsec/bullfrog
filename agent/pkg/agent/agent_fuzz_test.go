package agent

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FuzzExtractDNSFromTCPPayload tests DNS-over-TCP payload parsing
// This is critical as it parses untrusted network data
func FuzzExtractDNSFromTCPPayload(f *testing.F) {
	// Add seed corpus with valid DNS-over-TCP payloads
	f.Add([]byte{
		0x00, 0x1d, // Length: 29 bytes
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		// Question: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // Null terminator
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	})

	// Add edge cases
	f.Add([]byte{0x00, 0x00}) // Zero length
	f.Add([]byte{0x00, 0x01, 0x00}) // Minimal payload
	f.Add([]byte{}) // Empty payload

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		dns, err := extractDNSFromTCPPayload(data)
		if err == nil && dns != nil {
			// If parsing succeeded, verify basic DNS structure
			if len(dns.Questions) > 0 {
				// Access question to ensure it's valid
				_ = dns.Questions[0].Name
			}
		}
	})
}

// FuzzExtractDomainFromSRV tests SRV domain extraction
func FuzzExtractDomainFromSRV(f *testing.F) {
	// Add seed corpus
	f.Add("_https._tcp.example.com")
	f.Add("_http._tcp.test.org")
	f.Add("example.com")
	f.Add("*.example.com")
	f.Add("")

	f.Fuzz(func(t *testing.T, domain string) {
		// Should not panic on any input
		result := extractDomainFromSRV(domain)
		// Result should always be a valid string (may be same as input)
		_ = result
	})
}

// FuzzIsDomainAllowed tests domain matching logic with wildcards
func FuzzIsDomainAllowed(f *testing.F) {
	// Create agent with various domain patterns
	agent := &Agent{
		allowedDomains: map[string]bool{
			"example.com":      true,
			"*.github.com":     true,
			"*.*.example.org":  true,
			"test.*":           true,
		},
	}

	// Add seed corpus
	f.Add("example.com")
	f.Add("api.github.com")
	f.Add("sub.api.example.org")
	f.Add("test.com")
	f.Add("malicious.com")
	f.Add("")
	f.Add("*.evil.com")
	f.Add("example.com.evil.net")

	f.Fuzz(func(t *testing.T, domain string) {
		// Should not panic on any domain input
		result := agent.isDomainAllowed(domain)
		_ = result
	})
}

// FuzzIsIpAllowed tests IP and CIDR matching logic
func FuzzIsIpAllowed(f *testing.F) {
	// Create agent with various IP patterns
	agent := &Agent{
		allowedIps: map[string]bool{
			"127.0.0.1":        true,
			"192.168.1.1":      true,
		},
		allowedCIDR: []*net.IPNet{},
	}

	// Add a CIDR range
	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	agent.allowedCIDR = append(agent.allowedCIDR, cidr)

	// Add seed corpus
	f.Add("127.0.0.1")
	f.Add("192.168.1.1")
	f.Add("10.0.0.50")
	f.Add("8.8.8.8")
	f.Add("256.256.256.256") // Invalid IP
	f.Add("")
	f.Add("not-an-ip")
	f.Add("::1") // IPv6
	f.Add("2001:4860:4860::8888") // IPv6

	f.Fuzz(func(t *testing.T, ip string) {
		// Should not panic on any IP input
		result := agent.isIpAllowed(ip)
		_ = result
	})
}

// FuzzLoadAllowedIp tests IP/CIDR parsing logic
func FuzzLoadAllowedIp(f *testing.F) {
	// Add seed corpus
	f.Add("192.168.1.1")
	f.Add("10.0.0.0/8")
	f.Add("172.16.0.0/12")
	f.Add("")
	f.Add("invalid")
	f.Add("999.999.999.999")
	f.Add("10.0.0.0/99") // Invalid CIDR

	f.Fuzz(func(t *testing.T, ip string) {
		agent := &Agent{
			allowedIps:  make(map[string]bool),
			allowedCIDR: []*net.IPNet{},
		}

		// Should not panic on any IP/CIDR input
		agent.loadAllowedIp([]string{ip})
	})
}

// FuzzProcessDNSQuery tests DNS query processing with various inputs
func FuzzProcessDNSQuery(f *testing.F) {
	// Add seed corpus with domain names
	f.Add("example.com")
	f.Add("trusted.com")
	f.Add("_https._tcp.service.com")
	f.Add("")
	f.Add("*.wildcard.com")

	f.Fuzz(func(t *testing.T, domain string) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{"trusted.com"},
			AllowedIPs:      []string{},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		// Create a DNS query packet with the fuzzed domain
		// Use defer+recover to catch any panics
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic processing domain %q: %v", domain, r)
			}
		}()

		// Try to process a DNS query for this domain
		// We build a minimal DNS query
		dns := &layers.DNS{
			QR:    false, // Query
			Questions: []layers.DNSQuestion{
				{
					Name:  []byte(domain),
					Type:  layers.DNSTypeA,
					Class: layers.DNSClassIN,
				},
			},
		}

		pkt := PacketInfo{
			SrcIP:   "127.0.0.1",
			SrcPort: "12345",
			DstIP:   "127.0.0.53",
			DstPort: "53",
		}

		// Process the DNS query
		result := agent.processDNSQuery(dns, pkt)
		_ = result
	})
}

// FuzzConnectionLog tests JSON marshaling of connection logs
func FuzzConnectionLog(f *testing.F) {
	// Add seed corpus
	f.Add("192.168.1.1", "12345", "8.8.8.8", "443", "TCP", "google.com")
	f.Add("", "", "", "", "", "")
	f.Add("malicious\x00input", "port\ninjection", "ip\"injection", "443", "proto'", "domain<script>")

	f.Fuzz(func(t *testing.T, srcIP, srcPort, dstIP, dstPort, protocol, domain string) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_AUDIT,
			DNSPolicy:       DNS_POLICY_ANY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      newMockFileSystem(),
			ProcProvider:    newMockProcProvider(),
		})

		// Should not panic when logging connections with arbitrary input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic logging connection: %v", r)
			}
		}()

		pkt := PacketInfo{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		}

		agent.addConnectionLog(pkt, "audit", protocol, domain, "test-reason")
	})
}

// FuzzProcessPacket tests the main packet processing pipeline
func FuzzProcessPacket(f *testing.F) {
	// This is a more complex fuzz test that tests the entire packet processing
	// We'll use gopacket to create packets from raw bytes

	// Add seed corpus with various packet types
	validTCPPacket := GenerateTCPPacket(
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		12345,
		443,
	)
	f.Add(validTCPPacket.Data())

	validDNSPacket := GenerateDNSRequestPacket("example.com", net.IP{127, 0, 0, 53})
	f.Add(validDNSPacket.Data())

	f.Add([]byte{}) // Empty packet
	f.Add([]byte{0x00}) // Minimal packet

	f.Fuzz(func(t *testing.T, data []byte) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{"example.com"},
			AllowedIPs:      []string{"8.8.8.8", "10.0.0.0/24"},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      newMockFileSystem(),
			ProcProvider:    newMockProcProvider(),
		})

		// Should not panic on any packet data
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Panic processing packet data: %v", r)
			}
		}()

		// Try to decode as Ethernet packet
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if packet != nil {
			_ = agent.ProcessPacket(packet)
		}

		// Also try as IPv4
		packet = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
		if packet != nil {
			_ = agent.ProcessPacket(packet)
		}
	})
}
