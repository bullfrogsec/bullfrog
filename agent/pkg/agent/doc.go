// Package agent provides network egress monitoring and policy enforcement
// for GitHub Actions runners.
//
// The agent intercepts network packets using Linux NFQueue, enforces DNS
// and egress policies, and logs all connection attempts.
//
// Basic usage:
//
//	config := agent.AgentConfig{
//	    DNSPolicy:      agent.DNS_POLICY_ALLOWED_DOMAINS_ONLY,
//	    EgressPolicy:   agent.EGRESS_POLICY_AUDIT,
//	    AllowedDomains: []string{"example.com", "*.github.com"},
//	    AllowedIPs:     []string{"127.0.0.1", "10.0.0.0/8"},
//	}
//
//	a := agent.NewAgent(config)
//	verdict := a.ProcessPacket(packet)
//
// The package supports Docker container process identification and
// comprehensive connection logging.
package agent
