package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"sync"
	"time"

	"flag"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

var (
	blocking       = false
	defaultDomains = []string{"github.com", "api.github.com", "*.actions.githubusercontent.com", "results-receiver.actions.githubusercontent.com", "*.blob.core.windows.net"}
	defaultIps     = []string{"168.63.129.16", "169.254.169.254", "127.0.0.1"}
)

func loadAllowedDomain(filename string, allowedDomains map[string]bool) error {

	fmt.Println("loading allowed domains")

	// loads default first
	for _, domain := range defaultDomains {
		allowedDomains[domain] = true
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("No %s file found, using defaults only\n", filename)
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		allowedDomains[line] = true
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func loadAllowedIp(filename string, allowedIps map[string]bool, allowedCIDR *[]*net.IPNet) error {

	fmt.Println("loading allowed ips")

	// loads default first
	for _, ip := range defaultIps {
		allowedIps[ip] = true
		addIpToLogs("allowed", "unknown", ip)
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("No %s file found, using defaults only\n", filename)
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// fmt.Printf("line: %s", line)
		_, cidr, err := net.ParseCIDR(line)
		if err == nil {
			fmt.Printf("CIDR: %s\n", cidr)
			*allowedCIDR = append(*allowedCIDR, cidr)
		} else {
			fmt.Printf("error parsing CIDR: %v\n", err)
			allowedIps[line] = true
			addIpToLogs("allowed", "unknown", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func addToNftables(ips map[string]bool, cidr []*net.IPNet) error {
	if !blocking {
		return nil
	}
	for ip := range ips {
		err := addIpToNftables(ip)
		if err != nil {
			return fmt.Errorf("Error adding %s to nftables: %v\n", ip, err)
		}
	}
	for _, c := range cidr {
		err := addIpToNftables(c.String())
		if err != nil {
			return fmt.Errorf("Error adding %s to nftables: %v\n", c.String(), err)
		}
	}
	return nil
}

func addIpToNftables(ip string) error {
	if !blocking {
		return nil
	}
	ip_str := fmt.Sprintf("{ %s }", ip)

	{
		cmd := exec.Command("nft", "add", "element", "inet", "filter", "allowed_ips", ip_str)
		err := cmd.Run()
		if err != nil {
			return err
		}
		fmt.Printf("nft add element inet filter allowed_ips %s\n", ip)
	}

	// Docker as well (ip vs inet)
	{
		cmd := exec.Command("nft", "add", "element", "ip", "filter", "allowed_ips", ip_str)
		err := cmd.Run()
		if err != nil {
			return err
		}
		fmt.Printf("nft add element ip filter allowed_ips %s\n", ip)
	}

	return nil
}

func isDomainAllowed(domain string, allowedDomains map[string]bool) bool {
	if allowedDomains[domain] {
		return true
	}
	for allowedDomain := range allowedDomains {
		match, _ := path.Match(allowedDomain, domain)
		if match {
			return true
		}
	}
	return false
}

func isIpAllowed(ipStr string, allowedIps map[string]bool, allowedCIDR []*net.IPNet) bool {
	if allowedIps[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Printf("Failed to parse IP: %s\n", ipStr)
		return false
	}
	for _, cidr := range allowedCIDR {
		if cidr.Contains(ip) {
			allowedIps[ipStr] = true
			return true
		}
	}
	return false
}

var decisionLogsMutex sync.Mutex

func addIpToLogs(decision string, domain string, ip string) {
	decisionLogsMutex.Lock()
	defer decisionLogsMutex.Unlock()

	if _, err := os.Stat("/var/log/gha-agent"); os.IsNotExist(err) {
		os.Mkdir("/var/log/gha-agent", 0755)
	}

	f, err := os.OpenFile("/var/log/gha-agent/decisions.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("failed to open /var/log/gha-agent/decisions.log")
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "%d|%s|%s|%s\n", time.Now().Unix(), decision, domain, ip)
}

func main() {
	// set the mode (audit or block) based on the program argument
	blockDNS := false

	modeFlag := flag.String("mode", "audit", "Mode: audit or block")
	blockDNSFlag := flag.Bool("block-dns", false, "Enable DNS blocking")
	flag.Parse()

	if *modeFlag == "block" {
		blocking = true
		fmt.Println("Blocking mode enabled")
	} else {
		fmt.Println("Audit mode enabled")
	}

	if blocking {
		if *blockDNSFlag {
			blockDNS = true
			fmt.Println("DNS queries to unallowed domains will be blocked")
			// With this option enabled, the queue will receive DNS queries and not responses
		}
	}

	allowedDomains := make(map[string]bool)
	allowedIps := make(map[string]bool)
	allowedCIDR := []*net.IPNet{}

	err := loadAllowedIp("allowed_ips.txt", allowedIps, &allowedCIDR)
	if err != nil {
		log.Fatalf("Loading IP allowlist: %v", err)
	}

	err = loadAllowedDomain("allowed_domains.txt", allowedDomains)
	if err != nil {
		log.Fatalf("Loading domain allowlist: %v", err)
	}

	err = addToNftables(allowedIps, allowedCIDR)
	if err != nil {
		log.Fatalf("Error adding to nftables: %v", err)
	}

	nfq, err := netfilter.NewNFQueue(0, 1000, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	fmt.Println("Waiting for packets...")

	for p := range packets {
		packet := p.Packet
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {

			dns, _ := dnsLayer.(*layers.DNS)
			// fmt.Println("DNS ID: ", dns.ID)
			// fmt.Println("DNS QR: ", dns.QR) // true if this is a response, false if it's a query
			// fmt.Println("DNS OpCode: ", dns.OpCode)
			// fmt.Println("DNS ResponseCode: ", dns.ResponseCode)
			// for _, q := range dns.Questions {
			//         fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
			// }
			if blockDNS && !dns.QR {
				for _, q := range dns.Questions {
					if q.Type == layers.DNSTypeA {
						domain := string(q.Name)
						fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
						fmt.Print(domain)
						if isDomainAllowed(domain, allowedDomains) {
							fmt.Println("-> Allowed DNS Query")
							p.SetVerdict(netfilter.Verdict(netfilter.NF_ACCEPT))
						} else {
							fmt.Println("-> Blocked DNS Query")
							addIpToLogs("blocked", domain, "unknown")
							p.SetVerdict(netfilter.Verdict(netfilter.NF_DROP))
						}
					}
				}
			}
			for _, a := range dns.Answers {
				if a.Type == layers.DNSTypeA {
					fmt.Printf("DNS Answer: %s %s %s\n", a.Name, a.Type, a.IP)
					fmt.Printf("%s:%s", a.Name, a.IP)
					domain := string(dns.Questions[0].Name)
					ip := a.IP.String()
					if isDomainAllowed(domain, allowedDomains) {
						fmt.Println("-> Allowed request")
						if !allowedIps[ip] {
							err := addIpToNftables(ip)
							addIpToLogs("allowed", domain, ip)
							if err != nil {
								fmt.Printf("failed to add %s to NFT tables", ip)
							} else {
								allowedIps[ip] = true
							}
						}
					} else if isIpAllowed(ip, allowedIps, allowedCIDR) {
						fmt.Println("-> Allowed request")
						addIpToLogs("allowed", domain, ip)
					} else {
						addIpToLogs("blocked", domain, ip)
						if blocking {
							fmt.Println("-> Blocked request")
						} else {
							fmt.Println("-> Unallowed request")
						}
					}
				}
			}
		}
		p.SetVerdict(netfilter.Verdict(netfilter.NF_ACCEPT))
	}
}
