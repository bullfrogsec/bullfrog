package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/bullfrogsec/agent/pkg/agent"
)

func main() {
	allowedDomains := flag.String("allowed-domains", "", "Comma-separated list of allowed domains")
	allowedIPs := flag.String("allowed-ips", "", "Comma-separated list of allowed IPs or IP ranges in CIDR notation")
	dnsPolicy := flag.String("dns-policy", "allowed-domains-only", "DNS policy: allowed-domains-only or any")
	egressPolicy := flag.String("egress-policy", "audit", "Egress policy: audit or block")
	enableSudo := flag.Bool("enable-sudo", true, "Enable sudo: true or false")
	collectProcessInfo := flag.Bool("collect-process-info", true, "Collect process information: true or false")

	flag.Parse()

	agentInstance := agent.NewAgent(agent.AgentConfig{
		DNSPolicy:          *dnsPolicy,
		EgressPolicy:       *egressPolicy,
		AllowedDomains:     strings.Split(*allowedDomains, ","),
		AllowedIPs:         strings.Split(*allowedIPs, ","),
		EnableSudo:         *enableSudo,
		CollectProcessInfo: *collectProcessInfo,
		NetInfoProvider:    &agent.LinuxNetInfoProvider{},
		FileSystem:         &agent.FileSystem{},
		ProcProvider:       &agent.LinuxProcProvider{},
	})

	nfq, err := netfilter.NewNFQueue(0, 1000, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	fmt.Println("Waiting for packets...")
	setAgentIsReady()

	for p := range packets {
		verdict := agentInstance.ProcessPacket(p.Packet)
		if verdict == agent.ACCEPT_REQUEST {
			p.SetVerdict(netfilter.Verdict(netfilter.NF_ACCEPT))
		} else if verdict == agent.DROP_REQUEST {
			p.SetVerdict(netfilter.Verdict(netfilter.NF_DROP))
		}
	}
}
