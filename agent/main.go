package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/AkihiroSuda/go-netfilter-queue"
)

func main() {
	dnsPolicy := flag.String("dns-policy", "allowed-domains-only", "DNS policy: allowed-domains-only or any")
	egressPolicy := flag.String("egress-policy", "audit", "Egress policy: audit or block")
	flag.Parse()

	nft := NFTFirewall{}
	agent := NewAgent(&nft)
	agent.init(*egressPolicy, *dnsPolicy)

	nfq, err := netfilter.NewNFQueue(0, 1000, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	fmt.Println("Waiting for packets...")
	agent.setAgentIsReady()

	for p := range packets {
		verdict := agent.processPacket(p.Packet)
		if verdict == ACCEPT_REQUEST {
			p.SetVerdict(netfilter.Verdict(netfilter.NF_ACCEPT))
		} else if verdict == DROP_REQUEST {
			p.SetVerdict(netfilter.Verdict(netfilter.NF_DROP))
		}
	}
}
