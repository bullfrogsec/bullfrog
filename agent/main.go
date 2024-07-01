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

	fmt.Fprintf(f, "%d\n", time.Now().Unix())
}

func getDNSServer() (string, error) {
	networkInterface, err := exec.Command("sh", "-c", "ip route | grep default | awk '{print $5}'").Output()
    if err != nil {
        fmt.Printf("Error getting default network interface: %s\n", err)
        return "", err
    }
	// remove new line of networkInterface
	networkInterface = networkInterface[:len(networkInterface)-1]
	fmt.Printf("Network interface: %s\n", networkInterface)

	cmd := fmt.Sprintf("resolvectl status %s | grep 'DNS Servers' | awk '{print $3}'", networkInterface)
	fmt.Printf("cmd: %s\n", cmd)

	dnsServer, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Println("Error getting DNS server: ", err)
		return "", err
	}
	// remove new line of dnsServer
	dnsServer = dnsServer[:len(dnsServer)-1]
	return string(dnsServer), nil
}

func loadAllowedDNSServers(allowedDNSServers map[string]bool) error {
	dnsServer, err := getDNSServer()
	if err != nil {
		return err
	}
	fmt.Printf("DNS Server: %s\n", dnsServer)
	allowedDNSServers[dnsServer] = true

	// trust systemd-resolved by default
	allowedDNSServers["127.0.0.53"] = true
	return nil
}

func getDestinationIP(packet *netfilter.NFPacket) (string, error) {
	ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Packet.Layer(layers.LayerTypeIPv6)
	}
	if ipLayer == nil {
		return "", fmt.Errorf("Failed to get IP layer")
	}
	ip, _ := ipLayer.(*layers.IPv4)
	if ip == nil {
		ip6, _ := ipLayer.(*layers.IPv6)
		if ip6 == nil {
			return "", fmt.Errorf("Failed to get IP layer")
		}
		return ip6.DstIP.String(), nil
	}
	return ip.DstIP.String(), nil
}

func main() {
	// set the mode (audit or block) based on the program argument
	blockDNS := false

	dnsPolicy := flag.String("dns-policy", "allowed-domains-only", "DNS policy: allowed-domains-only or any")
	egressPolicy := flag.String("egress-policy", "audit", "Egress policy: audit or block")
	flag.Parse()

	if *egressPolicy == "block" {
		blocking = true
		fmt.Println("Blocking mode enabled")
	} else {
		fmt.Println("Audit mode enabled")
	}

	if blocking {
		if *dnsPolicy == "allowed-domains-only" {
			blockDNS = true
			fmt.Println("DNS queries to unallowed domains will be blocked")
			// With this option enabled, the queue will receive DNS queries and not responses
		}
	}

	allowedDomains := make(map[string]bool)
	allowedIps := make(map[string]bool)
	allowedDNSServers := make(map[string]bool)
	allowedCIDR := []*net.IPNet{}

	err := loadAllowedIp("allowed_ips.txt", allowedIps, &allowedCIDR)
	if err != nil {
		log.Fatalf("Loading IP allowlist: %v", err)
	}

	err = loadAllowedDomain("allowed_domains.txt", allowedDomains)
	if err != nil {
		log.Fatalf("Loading domain allowlist: %v", err)
	}

	err = loadAllowedDNSServers(allowedDNSServers)
	if err != nil {
		log.Fatalf("Loading DNS servers allowlist: %v", err)
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
	setAgentIsReady()

	for p := range packets {
		packet := p.Packet
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {

			dns, _ := dnsLayer.(*layers.DNS)
			fmt.Println("DNS ID: ", dns.ID)
			fmt.Println("DNS QR: ", dns.QR) // true if this is a response, false if it's a query
			fmt.Println("DNS OpCode: ", dns.OpCode)
			fmt.Println("DNS ResponseCode: ", dns.ResponseCode)
			for _, q := range dns.Questions {
			        fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
			}
			// if we are blocking DNS queries, intercept the DNS queries and decide whether to block or allow them
			if blockDNS && !dns.QR {
				for _, q := range dns.Questions {
					if q.Type == layers.DNSTypeA || q.Type == layers.DNSTypeCNAME {
						domain := string(q.Name)
						fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
						fmt.Print(domain)

						// making sure the DNS query is using a trusted DNS server
						destinationIP, err := getDestinationIP(&p)
						if err != nil {
							fmt.Println("Failed to get destination IP")
							addIpToLogs("blocked", domain, "unknown")
							p.SetVerdict(netfilter.Verdict(netfilter.NF_DROP))
							continue
						}
						if !allowedDNSServers[destinationIP] {
							fmt.Printf("-> Blocked DNS Query. Untrusted DNS server %s\n", destinationIP)
							addIpToLogs("blocked", domain, "unknown")
							p.SetVerdict(netfilter.Verdict(netfilter.NF_DROP))
							continue
						}

						if isDomainAllowed(domain, allowedDomains) {
							fmt.Println("-> Allowed DNS Query")
							p.SetVerdict(netfilter.Verdict(netfilter.NF_ACCEPT))
							continue
						} 
						fmt.Println("-> Blocked DNS Query")
						addIpToLogs("blocked", domain, "unknown")
						p.SetVerdict(netfilter.Verdict(netfilter.NF_DROP))
						continue
					}
				}
			}
			// interface DNS responses so we can allow IPs from allowed domains
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
				} else if a.Type == layers.DNSTypeCNAME {	// dynamically add cname records to the allowlist
					cnameDomain := string(a.CNAME)
					fmt.Printf("DNS Answer: %s %s %s\n", a.Name, a.Type, cnameDomain)
					fmt.Printf("%s:%s", a.Name, cnameDomain)
					domainQuery := string(dns.Questions[0].Name)
					if isDomainAllowed(domainQuery, allowedDomains) {
						fmt.Println("-> Allowed request")
						if !allowedDomains[cnameDomain] {
							fmt.Printf("Adding %s to the allowed domains list\n", cnameDomain)
							allowedDomains[cnameDomain] = true
						}
					} 
				}
			}
		}
		p.SetVerdict(netfilter.Verdict(netfilter.NF_ACCEPT))
	}
}
