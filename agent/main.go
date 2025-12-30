package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
)

func setAgentIsReady() {
	if _, err := os.Stat("/var/run/bullfrog"); os.IsNotExist(err) {
		os.Mkdir("/var/run/bullfrog", 0755)
	}

	f, err := os.OpenFile("/var/run/bullfrog/agent-ready", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("failed to open /var/run/bullfrog/agent-ready")
		return
	}
	defer f.Close()
	now := time.Now().Unix()
	fmt.Printf("Agent is ready at %d\n", now)
	fmt.Fprintf(f, "%d\n", now)
}

func main() {
	allowedDomains := flag.String("allowed-domains", "", "Comma-separated list of allowed domains")
	allowedIPs := flag.String("allowed-ips", "", "Comma-separated list of allowed IPs or IP ranges in CIDR notation")
	dnsPolicy := flag.String("dns-policy", "allowed-domains-only", "DNS policy: allowed-domains-only or any")
	egressPolicy := flag.String("egress-policy", "audit", "Egress policy: audit or block")
	enableSudo := flag.Bool("enable-sudo", true, "Enable sudo: true or false")
	collectProcessInfo := flag.Bool("collect-process-info", true, "Collect process information: true or false")

	flag.Parse()

	agent := NewAgent(AgentConfig{
		DNSPolicy:          *dnsPolicy,
		EgressPolicy:       *egressPolicy,
		AllowedDomains:     strings.Split(*allowedDomains, ","),
		AllowedIPs:         strings.Split(*allowedIPs, ","),
		EnableSudo:         *enableSudo,
		CollectProcessInfo: *collectProcessInfo,
		NetInfoProvider:    &LinuxNetInfoProvider{},
		FileSystem:         &FileSystem{},
		ProcProvider:       &LinuxProcProvider{},
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
		verdict := agent.ProcessPacket(p.Packet)
		if verdict == ACCEPT_REQUEST {
			p.SetVerdict(netfilter.Verdict(netfilter.NF_ACCEPT))
		} else if verdict == DROP_REQUEST {
			p.SetVerdict(netfilter.Verdict(netfilter.NF_DROP))
		}
	}
}
