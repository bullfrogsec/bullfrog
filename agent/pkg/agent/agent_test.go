package agent

import (
	"net"
	"testing"

	"github.com/google/gopacket"
)

func TestNewAgent(t *testing.T) {
	tests := []struct {
		name         string
		config       AgentConfig
		wantErr      bool
		wantBlocking bool
		wantBlockDNS bool
	}{
		{
			name: "Block DNS",
			config: AgentConfig{
				EgressPolicy:    EGRESS_POLICY_BLOCK,
				DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
				AllowedDomains:  []string{},
				AllowedIPs:      []string{"10.0.0.0/24"},
				EnableSudo:      true,
				NetInfoProvider: &mockNetInfoProvider{},
				FileSystem:      &mockFileSystem{},
			},
			wantErr:      false,
			wantBlocking: true,
			wantBlockDNS: true,
		},
		{
			name: "Allow DNS",
			config: AgentConfig{
				EgressPolicy:    EGRESS_POLICY_BLOCK,
				DNSPolicy:       DNS_POLICY_ANY,
				AllowedDomains:  []string{""},
				AllowedIPs:      []string{"127.0.0.1"},
				EnableSudo:      true,
				NetInfoProvider: &mockNetInfoProvider{},
				FileSystem:      &mockFileSystem{},
			},
			wantErr:      false,
			wantBlocking: true,
			wantBlockDNS: false,
		},
		{
			name: "Allow DNS during audit",
			config: AgentConfig{
				EgressPolicy:    EGRESS_POLICY_AUDIT,
				DNSPolicy:       DNS_POLICY_ANY,
				AllowedDomains:  []string{"example.com"},
				AllowedIPs:      []string{""},
				EnableSudo:      true,
				NetInfoProvider: &mockNetInfoProvider{},
				FileSystem:      &mockFileSystem{},
			},
			wantErr:      false,
			wantBlocking: false,
			wantBlockDNS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := NewAgent(tt.config)
			if (agent == nil) != tt.wantErr {
				t.Errorf("NewAgent() error = %v, wantErr %v", agent == nil, tt.wantErr)
				return
			}
			if agent.blocking != tt.wantBlocking {
				t.Errorf("NewAgent() blocking = %v, wantBlocking %v", agent.blocking, tt.wantBlocking)
			}
			if agent.blockDNS != tt.wantBlockDNS {
				t.Errorf("NewAgent() blockDNS = %v, wantBlockDNS %v", agent.blockDNS, tt.wantBlockDNS)
			}
		})
	}
}

func TestProcessDNSQueryPacket(t *testing.T) {

	blockDNSAgent := NewAgent(AgentConfig{
		EgressPolicy:    EGRESS_POLICY_BLOCK,
		DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
		AllowedDomains:  []string{"trusted.com"},
		AllowedIPs:      []string{""},
		EnableSudo:      true,
		NetInfoProvider: &mockNetInfoProvider{},
		FileSystem:      &mockFileSystem{},
		ProcProvider:    newMockProcProvider(),
	})
	noBlockDNSAgent := NewAgent(AgentConfig{
		EgressPolicy:    EGRESS_POLICY_BLOCK,
		DNSPolicy:       DNS_POLICY_ANY,
		AllowedDomains:  []string{"trusted.com"},
		AllowedIPs:      []string{""},
		EnableSudo:      true,
		NetInfoProvider: &mockNetInfoProvider{},
		FileSystem:      &mockFileSystem{},
		ProcProvider:    newMockProcProvider(),
	})

	tests := []struct {
		name   string
		packet gopacket.Packet
		agent  *Agent
		want   uint8
	}{
		{
			name:   "Accept DNS query to trusted.com",
			packet: GenerateDNSRequestPacket("trusted.com", net.IP{127, 0, 0, 53}),
			agent:  blockDNSAgent,
			want:   ACCEPT_REQUEST,
		},
		{
			name:   "Drop DNS query to blocked.com",
			packet: GenerateDNSRequestPacket("blocked.com", net.IP{127, 0, 0, 53}),
			agent:  blockDNSAgent,
			want:   DROP_REQUEST,
		},
		{
			name:   "Drop DNS query using untrusted DNS server but trusted domain",
			packet: GenerateDNSRequestPacket("trusted.com", net.IP{8, 8, 8, 8}),
			agent:  blockDNSAgent,
			want:   DROP_REQUEST,
		},
		{
			name:   "Acccept DNS SRV query to _https._tcp.trusted.com",
			packet: GenerateDNSTypeSRVRequestPacket("_https._tcp.trusted.com", net.IP{127, 0, 0, 53}),
			agent:  blockDNSAgent,
			want:   ACCEPT_REQUEST,
		},
		{
			name:   "Acccept DNS query to blocked.com when not blocking DNS",
			packet: GenerateDNSRequestPacket("blocked.com", net.IP{127, 0, 0, 53}),
			agent:  noBlockDNSAgent,
			want:   ACCEPT_REQUEST,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.agent.ProcessPacket(tt.packet)
			if got != tt.want {
				t.Errorf("ProcessPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessDNSResponseAPacket(t *testing.T) {

	type want struct {
		decision         uint8
		ip               string
		allowListPresent bool
	}

	tests := []struct {
		name   string
		packet gopacket.Packet
		want   want
	}{
		{
			name:   "Allow IP to trusted.com",
			packet: GenerateDNSTypeAResponsePacket("trusted.com", net.IP{123, 123, 123, 123}, net.IP{127, 0, 0, 53}),
			want: want{
				decision:         ACCEPT_REQUEST,
				ip:               "123.123.123.123",
				allowListPresent: true,
			},
		},
		{
			name:   "Do not allow IP to blocked.com",
			packet: GenerateDNSTypeAResponsePacket("blocked.com", net.IP{110, 110, 110, 110}, net.IP{127, 0, 0, 53}),
			want: want{
				decision:         ACCEPT_REQUEST,
				ip:               "110.110.110.110",
				allowListPresent: false,
			},
		},
	}

	agentConfig := AgentConfig{
		EgressPolicy:    EGRESS_POLICY_BLOCK,
		DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
		AllowedDomains:  []string{"trusted.com"},
		AllowedIPs:      []string{""},
		EnableSudo:      true,
		NetInfoProvider: &mockNetInfoProvider{},
		FileSystem:      &mockFileSystem{},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := NewAgent(agentConfig)
			got := agent.ProcessPacket(tt.packet)
			if got != tt.want.decision {
				t.Errorf("ProcessPacket() = %v, want %v", got, tt.want)
			}
			if agent.allowedIps[tt.want.ip] != tt.want.allowListPresent {
				t.Errorf("ProcessPacket() = %v, want %v", agent.allowedIps[tt.want.ip], tt.want.allowListPresent)
			}
		})
	}
}

func TestProcessDNSResponseCNAMEPacket(t *testing.T) {

	type want struct {
		decision         uint8
		domain           string
		allowListPresent bool
	}

	tests := []struct {
		name   string
		packet gopacket.Packet
		want   want
	}{
		{
			name:   "Allow cname for trusted.com",
			packet: GenerateDNSTypeCNAMEResponsePacket("trusted.com", "cname-value.com", net.IP{127, 0, 0, 53}),
			want: want{
				decision:         ACCEPT_REQUEST,
				domain:           "cname-value.com",
				allowListPresent: true,
			},
		},
		{
			name:   "Do no allow cname for blocked.com",
			packet: GenerateDNSTypeCNAMEResponsePacket("blocked.com", "cname-value.com", net.IP{127, 0, 0, 53}),
			want: want{
				decision:         ACCEPT_REQUEST,
				domain:           "cname-value.com",
				allowListPresent: false,
			},
		},
	}

	agentConfig := AgentConfig{
		EgressPolicy:    EGRESS_POLICY_BLOCK,
		DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
		AllowedDomains:  []string{"trusted.com"},
		AllowedIPs:      []string{""},
		EnableSudo:      true,
		NetInfoProvider: &mockNetInfoProvider{},
		FileSystem:      &mockFileSystem{},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := NewAgent(agentConfig)
			got := agent.ProcessPacket(tt.packet)
			if got != tt.want.decision {
				t.Errorf("ProcessPacket() = %v, want %v", got, tt.want)
			}
			if agent.allowedDomains[tt.want.domain] != tt.want.allowListPresent {
				t.Errorf("ProcessPacket() = %v, want %v", agent.allowedDomains[tt.want.domain], tt.want.allowListPresent)
			}
		})
	}
}

func TestExtractDomainFromSRVRequest(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{
			name:   "Extract domain from https request",
			domain: "_https._tcp.example.com",
			want:   "example.com",
		},
		{
			name:   "Extract domain from http request",
			domain: "_http._tcp.example.com",
			want:   "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomainFromSRV(tt.domain)
			if got != tt.want {
				t.Errorf("extractDomainFromSRV() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessNonDNSPacket(t *testing.T) {
	// Test TCP packet with allowed IP
	t.Run("Accept TCP packet to allowed IP", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{"93.184.216.34"},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST, got %v", decision)
		}
	})

	// Test TCP packet with allowed IP from domain resolution
	t.Run("Accept TCP packet to IP resolved from allowed domain", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{"example.com"},
			AllowedIPs:      []string{},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		// First, simulate DNS response to add IP to allowlist
		dnsResponse := GenerateDNSTypeAResponsePacket(
			"example.com",
			net.IP{93, 184, 216, 34},
			net.IP{127, 0, 0, 53},
		)
		agent.ProcessPacket(dnsResponse)

		// Now test TCP packet to that IP
		tcpPacket := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		decision := agent.ProcessPacket(tcpPacket)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST, got %v", decision)
		}

		// Verify IP-to-domain mapping exists
		if domain, exists := agent.ipToDomain["93.184.216.34"]; !exists || domain != "example.com" {
			t.Errorf("Expected IP-to-domain mapping, got domain=%v, exists=%v", domain, exists)
		}
	})

	// Test TCP packet to blocked IP in block mode
	t.Run("Drop TCP packet to blocked IP in block mode", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{"10.0.0.1"},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34}, // Not in allowlist
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST, got %v", decision)
		}
	})

	// Test TCP packet to blocked IP in audit mode
	t.Run("Accept TCP packet to blocked IP in audit mode", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_AUDIT,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{"10.0.0.1"},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34}, // Not in allowlist
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST (audit mode), got %v", decision)
		}
	})

	// Test UDP packet with allowed IP
	t.Run("Accept UDP packet to allowed IP", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{"8.8.8.8"},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateUDPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{8, 8, 8, 8},
			12345,
			123, // NTP port
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST, got %v", decision)
		}
	})

	// Test UDP packet to blocked IP
	t.Run("Drop UDP packet to blocked IP", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateUDPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{8, 8, 8, 8},
			12345,
			123,
		)

		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST, got %v", decision)
		}
	})

	// Test packet without network layer
	t.Run("Drop packet without network layer", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GeneratePacketWithoutNetworkLayer()

		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST for packet without network layer, got %v", decision)
		}
	})

	// Test CIDR range matching
	t.Run("Accept TCP packet to IP in CIDR range", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{"10.0.0.0/24"}, // CIDR range
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{10, 0, 0, 50}, // Within 10.0.0.0/24
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for IP in CIDR range, got %v", decision)
		}
	})

	// Test default allowed IPs (127.0.0.1, 169.254.169.254)
	t.Run("Accept TCP packet to localhost", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{}, // Empty, but defaults include 127.0.0.1
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{127, 0, 0, 1},
			12345,
			8080,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for localhost, got %v", decision)
		}
	})

	// Test metadata service IP (169.254.169.254)
	t.Run("Accept TCP packet to metadata service", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{}, // Empty, but defaults include 169.254.169.254
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{169, 254, 169, 254},
			12345,
			80,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for metadata service IP, got %v", decision)
		}
	})
}

func TestProcessDNSOverTCP(t *testing.T) {
	// Test valid DNS over TCP with allowed domain
	t.Run("Accept valid DNS over TCP query to allowed domain", func(t *testing.T) {
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

		packet := GenerateDNSOverTCPPacket("trusted.com", net.IP{127, 0, 0, 53}, true)
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST, got %v", decision)
		}
	})

	// Test valid DNS over TCP with blocked domain
	t.Run("Block valid DNS over TCP query to blocked domain", func(t *testing.T) {
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

		packet := GenerateDNSOverTCPPacket("blocked.com", net.IP{127, 0, 0, 53}, true)
		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST, got %v", decision)
		}
	})

	// Test DNS over TCP with untrusted DNS server
	t.Run("Block DNS over TCP to untrusted DNS server", func(t *testing.T) {
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

		packet := GenerateDNSOverTCPPacket("trusted.com", net.IP{8, 8, 8, 8}, true)
		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST for untrusted DNS server, got %v", decision)
		}
	})

	// Test DNS over TCP with empty payload (connection establishment)
	t.Run("Accept DNS over TCP with empty payload", func(t *testing.T) {
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

		packet := GenerateDNSOverTCPPacket("", net.IP{127, 0, 0, 53}, false)
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for empty payload, got %v", decision)
		}
	})

	// Test DNS over TCP with invalid payload
	t.Run("Drop DNS over TCP with invalid payload", func(t *testing.T) {
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

		packet := GenerateDNSOverTCPPacketWithInvalidPayload(net.IP{127, 0, 0, 53})
		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST for invalid payload, got %v", decision)
		}
	})

	// Test DNS over TCP response
	t.Run("Accept DNS over TCP response", func(t *testing.T) {
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

		// DNS response (from server to client)
		packet := GenerateDNSOverTCPResponse("trusted.com", net.IP{123, 123, 123, 123}, net.IP{127, 0, 0, 53})
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for DNS response, got %v", decision)
		}

		// Verify IP was added to allowlist
		if !agent.allowedIps["123.123.123.123"] {
			t.Errorf("Expected IP to be added to allowlist")
		}
	})

	// Test DNS over TCP when not blocking DNS
	t.Run("Accept DNS over TCP when not blocking DNS", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ANY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateDNSOverTCPPacket("any-domain.com", net.IP{127, 0, 0, 53}, true)
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST when not blocking DNS, got %v", decision)
		}
	})
}

func TestProcessInfoCollection(t *testing.T) {
	// Test process info collection disabled
	t.Run("Return unknown process info when collection disabled", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{"93.184.216.34"},
			EnableSudo:         true,
			CollectProcessInfo: false, // Disabled
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         &mockFileSystem{},
			ProcProvider:       newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		agent.ProcessPacket(packet)

		// Process info should be "unknown"
		cacheKey := "127.0.0.1:12345:tcp"
		if cached, exists := agent.processInfoCache[cacheKey]; exists {
			t.Errorf("Expected no cache entry when collection disabled, got %v", cached)
		}
	})

	// Test process info collection enabled with cache
	t.Run("Cache process info when collection enabled", func(t *testing.T) {
		// Create a custom mock provider that returns socket entries
		mockProc := &mockProcProviderWithSockets{
			mockProcProvider: mockProcProvider{
				InodeToPID:    map[uint64]int{12345: 1000},
				PIDToName:     map[int]string{1000: "curl"},
				PIDToCmdLine:  map[int]string{1000: "curl https://example.com"},
				PIDToExecPath: map[int]string{1000: "/usr/bin/curl"},
			},
		}

		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{"93.184.216.34"},
			EnableSudo:         true,
			CollectProcessInfo: true, // Enabled
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         &mockFileSystem{},
			ProcProvider:       mockProc,
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		agent.ProcessPacket(packet)

		// Check cache
		cacheKey := "127.0.0.1:12345:tcp"
		cached, exists := agent.processInfoCache[cacheKey]
		if !exists {
			t.Errorf("Expected cache entry for process info")
		}
		if cached.PID != 1000 {
			t.Errorf("Expected PID 1000, got %d", cached.PID)
		}
		if cached.ProcessName != "curl" {
			t.Errorf("Expected process name 'curl', got %s", cached.ProcessName)
		}
	})

	// Test cache hit on second request
	t.Run("Use cached process info on second request", func(t *testing.T) {
		mockProc := &mockProcProviderWithCallCount{
			mockProcProviderWithSockets: mockProcProviderWithSockets{
				mockProcProvider: mockProcProvider{
					InodeToPID:    map[uint64]int{12345: 1000},
					PIDToName:     map[int]string{1000: "curl"},
					PIDToCmdLine:  map[int]string{1000: "curl https://example.com"},
					PIDToExecPath: map[int]string{1000: "/usr/bin/curl"},
				},
			},
		}

		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{"93.184.216.34"},
			EnableSudo:         true,
			CollectProcessInfo: true,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         &mockFileSystem{},
			ProcProvider:       mockProc,
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		// First request - should populate cache
		agent.ProcessPacket(packet)
		firstCallCount := mockProc.callCount

		// Second request - should use cache
		agent.ProcessPacket(packet)

		if mockProc.callCount != firstCallCount {
			t.Errorf("Expected cached lookup on second request, but ReadProcNetFile was called again")
		}
	})

	// Test DNS response packets skip process lookup (source port 53)
	t.Run("Skip process lookup for DNS response packets", func(t *testing.T) {
		mockProc := &mockProcProviderWithCallCount{
			mockProcProviderWithSockets: mockProcProviderWithSockets{
				mockProcProvider: mockProcProvider{
					InodeToPID:    make(map[uint64]int),
					PIDToName:     make(map[int]string),
					PIDToCmdLine:  make(map[int]string),
					PIDToExecPath: make(map[int]string),
				},
			},
		}

		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{"trusted.com"},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: true,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         &mockFileSystem{},
			ProcProvider:       mockProc,
		})

		// DNS response has source port 53 - should not trigger process lookup
		packet := GenerateDNSTypeAResponsePacket("trusted.com", net.IP{123, 123, 123, 123}, net.IP{127, 0, 0, 53})
		agent.ProcessPacket(packet)

		if mockProc.callCount > 0 {
			t.Errorf("Expected no process lookup for DNS response packet, but ReadProcNetFile was called %d times", mockProc.callCount)
		}
	})

	// Test Docker container process lookup
	t.Run("Extract process info from Docker container", func(t *testing.T) {
		mockDocker := newMockDockerProvider()

		// Setup a container with IP from Docker network range
		dockerIP := "172.17.0.2"
		mockDocker.Containers[dockerIP] = &mockContainerInfo{
			ID:      "abc123456789",
			Name:    "my-container",
			Image:   "nginx:latest",
			RootPID: 12345,
		}

		// Setup process info for the container
		containerKey := "abc123456789:172.17.0.2:8080:tcp"
		mockDocker.ProcessMap[containerKey] = &mockProcessDetails{
			PID:         100,
			ProcessName: "nginx",
			CommandLine: "nginx -g daemon off;",
			ExecPath:    "/usr/sbin/nginx",
		}

		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{"93.184.216.34"},
			EnableSudo:         true,
			CollectProcessInfo: true,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         newMockFileSystem(),
			ProcProvider:       newMockProcProvider(),
			DockerProvider:     mockDocker,
		})

		// Create packet from Docker container IP
		packet := GenerateTCPPacket(
			net.ParseIP(dockerIP),
			net.IP{93, 184, 216, 34},
			8080,
			443,
		)

		agent.ProcessPacket(packet)

		// Check that process info was cached with Docker details
		cacheKey := "172.17.0.2:8080:tcp"
		cached, exists := agent.processInfoCache[cacheKey]
		if !exists {
			t.Errorf("Expected cache entry for Docker process")
			return
		}

		if cached.PID != 100 {
			t.Errorf("Expected PID 100 from Docker, got %d", cached.PID)
		}
		if cached.ProcessName != "nginx" {
			t.Errorf("Expected process name 'nginx', got %s", cached.ProcessName)
		}
		if cached.Docker == nil {
			t.Errorf("Expected Docker info to be populated")
			return
		}
		if cached.Docker.ContainerName != "my-container" {
			t.Errorf("Expected container name 'my-container', got %s", cached.Docker.ContainerName)
		}
		if cached.Docker.ContainerImage != "nginx:latest" {
			t.Errorf("Expected container image 'nginx:latest', got %s", cached.Docker.ContainerImage)
		}
	})

	// Test fallback to host process when Docker lookup fails
	t.Run("Fallback to host process when Docker lookup fails", func(t *testing.T) {
		mockDocker := newMockDockerProvider()

		// Use 127.0.0.1 which our mock proc provider can handle
		// But trick it into thinking it's a Docker IP by adding to Docker containers
		testIP := "172.17.0.3"
		mockDocker.Containers[testIP] = &mockContainerInfo{
			ID:      "def987654321",
			Name:    "failing-container",
			Image:   "app:latest",
			RootPID: 99999,
		}
		// Intentionally not adding ProcessMap entry to simulate Docker process lookup failure

		// Use custom mock that can handle the specific IP
		mockProc := &mockProcProviderForDockerFallback{
			mockProcProvider: mockProcProvider{
				InodeToPID:    map[uint64]int{12345: 2000},
				PIDToName:     map[int]string{2000: "python3"},
				PIDToCmdLine:  map[int]string{2000: "python3 app.py"},
				PIDToExecPath: map[int]string{2000: "/usr/bin/python3"},
			},
		}

		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{"93.184.216.34"},
			EnableSudo:         true,
			CollectProcessInfo: true,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         newMockFileSystem(),
			ProcProvider:       mockProc,
			DockerProvider:     mockDocker,
		})

		packet := GenerateTCPPacket(
			net.ParseIP(testIP),
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		agent.ProcessPacket(packet)

		// Check that process info was cached with host process details (fallback)
		cacheKey := "172.17.0.3:12345:tcp"
		cached, exists := agent.processInfoCache[cacheKey]
		if !exists {
			t.Errorf("Expected cache entry for host process (fallback)")
			return
		}

		if cached.PID != 2000 {
			t.Errorf("Expected PID 2000 from host fallback, got %d", cached.PID)
		}
		if cached.ProcessName != "python3" {
			t.Errorf("Expected process name 'python3' from fallback, got %s", cached.ProcessName)
		}
		// Docker should be nil since we fell back to host lookup
		if cached.Docker != nil {
			t.Errorf("Expected Docker info to be nil for host process fallback, got %v", cached.Docker)
		}
	})
}

func TestDomainWildcardMatching(t *testing.T) {
	tests := []struct {
		name           string
		allowedDomains []string
		testDomain     string
		shouldAllow    bool
	}{
		{
			name:           "Exact match",
			allowedDomains: []string{"example.com"},
			testDomain:     "example.com",
			shouldAllow:    true,
		},
		{
			name:           "Wildcard subdomain match",
			allowedDomains: []string{"*.example.com"},
			testDomain:     "api.example.com",
			shouldAllow:    true,
		},
		{
			name:           "Wildcard nested subdomain match",
			allowedDomains: []string{"*.example.com"},
			testDomain:     "api.us.example.com",
			shouldAllow:    true,
		},
		{
			name:           "Wildcard positioning subdomain match",
			allowedDomains: []string{"api.*.example.com"},
			testDomain:     "api.us.example.com",
			shouldAllow:    true,
		},
		{
			name:           "Wildcard subdomain no match",
			allowedDomains: []string{"*.example.com"},
			testDomain:     "example.com",
			shouldAllow:    false,
		},
		{
			name:           "Wildcard TLD match",
			allowedDomains: []string{"example.*"},
			testDomain:     "example.com",
			shouldAllow:    true,
		},
		{
			name:           "Wildcard TLD match alternative",
			allowedDomains: []string{"example.*"},
			testDomain:     "example.org",
			shouldAllow:    true,
		},
		{
			name:           "Full wildcard",
			allowedDomains: []string{"*"},
			testDomain:     "anything.com",
			shouldAllow:    true,
		},
		{
			name:           "Multiple patterns - first matches",
			allowedDomains: []string{"*.trusted.com", "safe.net"},
			testDomain:     "api.trusted.com",
			shouldAllow:    true,
		},
		{
			name:           "Multiple patterns - second matches",
			allowedDomains: []string{"*.trusted.com", "safe.net"},
			testDomain:     "safe.net",
			shouldAllow:    true,
		},
		{
			name:           "Multiple patterns - none match",
			allowedDomains: []string{"*.trusted.com", "safe.net"},
			testDomain:     "evil.com",
			shouldAllow:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := NewAgent(AgentConfig{
				EgressPolicy:    EGRESS_POLICY_BLOCK,
				DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
				AllowedDomains:  tt.allowedDomains,
				AllowedIPs:      []string{},
				EnableSudo:      true,
				NetInfoProvider: &mockNetInfoProvider{},
				FileSystem:      &mockFileSystem{},
				ProcProvider:    newMockProcProvider(),
			})

			packet := GenerateDNSRequestPacket(tt.testDomain, net.IP{127, 0, 0, 53})
			decision := agent.ProcessPacket(packet)

			expectedDecision := DROP_REQUEST
			if tt.shouldAllow {
				expectedDecision = ACCEPT_REQUEST
			}

			if decision != expectedDecision {
				t.Errorf("Domain %s with pattern %v: expected %v, got %v",
					tt.testDomain, tt.allowedDomains, expectedDecision, decision)
			}
		})
	}
}

func TestDNSSRVResponse(t *testing.T) {
	t.Run("Accept SRV response for allowed domain", func(t *testing.T) {
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

		packet := GenerateDNSTypeSRVResponsePacket("_https._tcp.trusted.com", "server.trusted.com", net.IP{127, 0, 0, 53})
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for SRV response, got %v", decision)
		}

		// Verify SRV target domain was added to allowlist
		if !agent.allowedDomains["server.trusted.com"] {
			t.Errorf("Expected SRV target domain to be added to allowlist")
		}
	})

	t.Run("Do not add SRV target for blocked domain", func(t *testing.T) {
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

		packet := GenerateDNSTypeSRVResponsePacket("_https._tcp.blocked.com", "server.blocked.com", net.IP{127, 0, 0, 53})
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST (DNS responses always accepted), got %v", decision)
		}

		// Verify SRV target domain was NOT added to allowlist
		if agent.allowedDomains["server.blocked.com"] {
			t.Errorf("Expected SRV target domain to NOT be added to allowlist for blocked domain")
		}
	})
}

func TestConnectionLogging(t *testing.T) {
	// Test that allowed connections are logged
	t.Run("Log allowed connection with correct fields", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{"93.184.216.34"},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 1 {
			t.Errorf("Expected 1 log entry, got %d", len(logs))
			return
		}

		log := logs[0]
		// Verify log contains expected fields (using camelCase JSON field names)
		if !contains(log, "\"decision\":\"allowed\"") {
			t.Errorf("Log missing decision field: %s", log)
		}
		if !contains(log, "\"protocol\":\"TCP\"") {
			t.Errorf("Log missing protocol field: %s", log)
		}
		if !contains(log, "\"srcIP\":\"127.0.0.1\"") {
			t.Errorf("Log missing srcIP field: %s", log)
		}
		if !contains(log, "\"dstIP\":\"93.184.216.34\"") {
			t.Errorf("Log missing dstIP field: %s", log)
		}
		if !contains(log, "\"dstPort\":\"443\"") {
			t.Errorf("Log missing dstPort field: %s", log)
		}
		if !contains(log, "\"reason\":\"ip-allowed\"") {
			t.Errorf("Log missing reason field: %s", log)
		}
	})

	// Test that blocked connections are logged
	t.Run("Log blocked connection in block mode", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 1 {
			t.Errorf("Expected 1 log entry, got %d", len(logs))
			return
		}

		log := logs[0]
		if !contains(log, "\"decision\":\"blocked\"") {
			t.Errorf("Log missing blocked decision: %s", log)
		}
		if !contains(log, "\"reason\":\"ip-not-allowed\"") {
			t.Errorf("Log missing reason: %s", log)
		}
	})

	// Test that audit mode connections are logged
	t.Run("Log audit decision in audit mode", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_AUDIT,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST in audit mode, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 1 {
			t.Errorf("Expected 1 log entry, got %d", len(logs))
			return
		}

		log := logs[0]
		if !contains(log, "\"decision\":\"audit\"") {
			t.Errorf("Log missing audit decision: %s", log)
		}
	})

	// Test DNS query logging
	t.Run("Log DNS query with domain name", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{"trusted.com"},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		packet := GenerateDNSRequestPacket("trusted.com", net.IP{127, 0, 0, 53})
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 1 {
			t.Errorf("Expected 1 log entry for DNS query, got %d", len(logs))
			return
		}

		log := logs[0]
		if !contains(log, "\"protocol\":\"DNS\"") {
			t.Errorf("Log missing DNS protocol: %s", log)
		}
		if !contains(log, "\"domain\":\"trusted.com\"") {
			t.Errorf("Log missing domain name: %s", log)
		}
		if !contains(log, "\"reason\":\"domain-allowed\"") {
			t.Errorf("Log missing reason: %s", log)
		}
	})

	// Test that blocked DNS queries are logged
	t.Run("Log blocked DNS query", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{"trusted.com"},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		packet := GenerateDNSRequestPacket("blocked.com", net.IP{127, 0, 0, 53})
		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 1 {
			t.Errorf("Expected 1 log entry, got %d", len(logs))
			return
		}

		log := logs[0]
		if !contains(log, "\"decision\":\"blocked\"") {
			t.Errorf("Log missing blocked decision: %s", log)
		}
		if !contains(log, "\"domain\":\"blocked.com\"") {
			t.Errorf("Log missing domain name: %s", log)
		}
		if !contains(log, "\"reason\":\"domain-not-allowed\"") {
			t.Errorf("Log missing reason: %s", log)
		}
	})

	// Test that default IPs are NOT logged (to reduce noise)
	t.Run("Do not log connections to default allowed IPs", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		// 169.254.169.254 is in defaultIps - should not be logged
		packet := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{169, 254, 169, 254},
			12345,
			80,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for metadata service, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 0 {
			t.Errorf("Expected 0 log entries for default IP, got %d: %v", len(logs), logs)
		}
	})

	// Test that domain-to-IP mapping is logged
	t.Run("Log connection with domain from DNS resolution", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{"example.com"},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		// First, DNS response to establish IP-to-domain mapping
		dnsResponse := GenerateDNSTypeAResponsePacket("example.com", net.IP{93, 184, 216, 34}, net.IP{127, 0, 0, 53})
		agent.ProcessPacket(dnsResponse)

		// Clear logs from DNS response
		mockFS.Clear()

		// Now a TCP connection to that IP should log with the domain name
		tcpPacket := GenerateTCPPacket(
			net.IP{127, 0, 0, 1},
			net.IP{93, 184, 216, 34},
			12345,
			443,
		)

		decision := agent.ProcessPacket(tcpPacket)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 1 {
			t.Errorf("Expected 1 log entry, got %d", len(logs))
			return
		}

		log := logs[0]
		if !contains(log, "\"domain\":\"example.com\"") {
			t.Errorf("Log should contain resolved domain name: %s", log)
		}
	})

	// Test that untrusted DNS server is logged
	t.Run("Log untrusted DNS server", func(t *testing.T) {
		mockFS := newMockFileSystem()
		agent := NewAgent(AgentConfig{
			EgressPolicy:       EGRESS_POLICY_BLOCK,
			DNSPolicy:          DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:     []string{"trusted.com"},
			AllowedIPs:         []string{},
			EnableSudo:         true,
			CollectProcessInfo: false,
			NetInfoProvider:    &mockNetInfoProvider{},
			FileSystem:         mockFS,
			ProcProvider:       newMockProcProvider(),
		})

		// DNS query to untrusted server (8.8.8.8)
		packet := GenerateDNSRequestPacket("trusted.com", net.IP{8, 8, 8, 8})
		decision := agent.ProcessPacket(packet)

		if decision != DROP_REQUEST {
			t.Errorf("Expected DROP_REQUEST for untrusted DNS server, got %v", decision)
		}

		logs := mockFS.GetLogs("/var/log/gha-agent/connections.log")
		if len(logs) != 1 {
			t.Errorf("Expected 1 log entry, got %d", len(logs))
			return
		}

		log := logs[0]
		if !contains(log, "\"reason\":\"untrusted-dns-server\"") {
			t.Errorf("Log missing untrusted DNS server reason: %s", log)
		}
		if !contains(log, "\"dstIP\":\"8.8.8.8\"") {
			t.Errorf("Log missing untrusted DNS server IP: %s", log)
		}
	})
}

func TestIPv6PacketHandling(t *testing.T) {
	// Test IPv6 TCP packet
	t.Run("Accept IPv6 TCP packet to allowed IP", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{"2001:4860:4860::8888"},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateIPv6TCPPacket(
			net.ParseIP("::1"),
			net.ParseIP("2001:4860:4860::8888"),
			12345,
			443,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for IPv6 packet, got %v", decision)
		}
	})

	// Test IPv6 UDP packet
	t.Run("Accept IPv6 UDP packet to allowed IP", func(t *testing.T) {
		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{},
			AllowedIPs:      []string{"2001:4860:4860::8844"},
			EnableSudo:      true,
			NetInfoProvider: &mockNetInfoProvider{},
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		packet := GenerateIPv6UDPPacket(
			net.ParseIP("::1"),
			net.ParseIP("2001:4860:4860::8844"),
			12345,
			123,
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for IPv6 UDP packet, got %v", decision)
		}
	})

	// Test IPv6 DNS query
	t.Run("Accept IPv6 DNS query to allowed domain", func(t *testing.T) {
		// Create a custom mock that includes IPv6 localhost in DNS servers
		mockNet := &mockNetInfoProviderIPv6{}

		agent := NewAgent(AgentConfig{
			EgressPolicy:    EGRESS_POLICY_BLOCK,
			DNSPolicy:       DNS_POLICY_ALLOWED_DOMAINS_ONLY,
			AllowedDomains:  []string{"trusted.com"},
			AllowedIPs:      []string{},
			EnableSudo:      true,
			NetInfoProvider: mockNet,
			FileSystem:      &mockFileSystem{},
			ProcProvider:    newMockProcProvider(),
		})

		// Use IPv6 localhost as DNS server (which is now in the allowedDNSServers)
		packet := GenerateIPv6DNSRequestPacket("trusted.com", net.ParseIP("::1"))
		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for IPv6 DNS query, got %v", decision)
		}
	})

	// Test IPv6 AAAA response
	t.Run("Process IPv6 AAAA DNS response", func(t *testing.T) {
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

		packet := GenerateDNSTypeAAAAResponsePacket(
			"trusted.com",
			net.ParseIP("2001:4860:4860::8888"),
			net.IP{127, 0, 0, 53},
		)

		decision := agent.ProcessPacket(packet)

		if decision != ACCEPT_REQUEST {
			t.Errorf("Expected ACCEPT_REQUEST for AAAA response, got %v", decision)
		}
	})
}
