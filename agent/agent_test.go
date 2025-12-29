package main

import (
	"net"
	"testing"

	testingUtils "github.com/bullfrogsec/agent/testing"
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
				NetInfoProvider: &testingUtils.NetInfoProvider{},
				FileSystem:      &testingUtils.FileSystem{},
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
				NetInfoProvider: &testingUtils.NetInfoProvider{},
				FileSystem:      &testingUtils.FileSystem{},
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
				NetInfoProvider: &testingUtils.NetInfoProvider{},
				FileSystem:      &testingUtils.FileSystem{},
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
		NetInfoProvider: &testingUtils.NetInfoProvider{},
		FileSystem:      &testingUtils.FileSystem{},
	})
	noBlockDNSAgent := NewAgent(AgentConfig{
		EgressPolicy:    EGRESS_POLICY_BLOCK,
		DNSPolicy:       DNS_POLICY_ANY,
		AllowedDomains:  []string{"trusted.com"},
		AllowedIPs:      []string{""},
		EnableSudo:      true,
		NetInfoProvider: &testingUtils.NetInfoProvider{},
		FileSystem:      &testingUtils.FileSystem{},
	})

	tests := []struct {
		name   string
		packet gopacket.Packet
		agent  *Agent
		want   uint8
	}{
		{
			name:   "Accept DNS query to trusted.com",
			packet: testingUtils.GenerateDNSRequestPacket("trusted.com", net.IP{127, 0, 0, 53}),
			agent:  blockDNSAgent,
			want:   ACCEPT_REQUEST,
		},
		{
			name:   "Drop DNS query to blocked.com",
			packet: testingUtils.GenerateDNSRequestPacket("blocked.com", net.IP{127, 0, 0, 53}),
			agent:  blockDNSAgent,
			want:   DROP_REQUEST,
		},
		{
			name:   "Drop DNS query using untrusted DNS server but trusted domain",
			packet: testingUtils.GenerateDNSRequestPacket("trusted.com", net.IP{8, 8, 8, 8}),
			agent:  blockDNSAgent,
			want:   DROP_REQUEST,
		},
		{
			name:   "Acccept DNS SRV query to _https._tcp.trusted.com",
			packet: testingUtils.GenerateDNSTypeSRVRequestPacket("_https._tcp.trusted.com", net.IP{127, 0, 0, 53}),
			agent:  blockDNSAgent,
			want:   ACCEPT_REQUEST,
		},
		{
			name:   "Acccept DNS query to blocked.com when not blocking DNS",
			packet: testingUtils.GenerateDNSRequestPacket("blocked.com", net.IP{127, 0, 0, 53}),
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
			packet: testingUtils.GenerateDNSTypeAResponsePacket("trusted.com", net.IP{123, 123, 123, 123}, net.IP{127, 0, 0, 53}),
			want: want{
				decision:         ACCEPT_REQUEST,
				ip:               "123.123.123.123",
				allowListPresent: true,
			},
		},
		{
			name:   "Do not allow IP to blocked.com",
			packet: testingUtils.GenerateDNSTypeAResponsePacket("blocked.com", net.IP{110, 110, 110, 110}, net.IP{127, 0, 0, 53}),
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
		NetInfoProvider: &testingUtils.NetInfoProvider{},
		FileSystem:      &testingUtils.FileSystem{},
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
			packet: testingUtils.GenerateDNSTypeCNAMEResponsePacket("trusted.com", "cname-value.com", net.IP{127, 0, 0, 53}),
			want: want{
				decision:         ACCEPT_REQUEST,
				domain:           "cname-value.com",
				allowListPresent: true,
			},
		},
		{
			name:   "Do no allow cname for blocked.com",
			packet: testingUtils.GenerateDNSTypeCNAMEResponsePacket("blocked.com", "cname-value.com", net.IP{127, 0, 0, 53}),
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
		NetInfoProvider: &testingUtils.NetInfoProvider{},
		FileSystem:      &testingUtils.FileSystem{},
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
