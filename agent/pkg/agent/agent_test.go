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
