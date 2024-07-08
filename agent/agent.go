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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	blocking          = false
	defaultDomains    = []string{"github.com", "api.github.com", "*.actions.githubusercontent.com", "results-receiver.actions.githubusercontent.com", "*.blob.core.windows.net"}
	defaultIps        = []string{"168.63.129.16", "169.254.169.254", "127.0.0.1"}
	defaultDNSServers = []string{"127.0.0.53"}
)

const (
	ACCEPT_REQUEST uint8 = 0
	DROP_REQUEST   uint8 = 1
)

type Agent struct {
	blockDNS          bool
	allowedDomains    map[string]bool
	allowedIps        map[string]bool
	allowedDNSServers map[string]bool
	allowedCIDR       []*net.IPNet
	firewall          IFirewall
	decisionLogsMutex sync.Mutex
}

func NewAgent(firewall IFirewall) *Agent {
	return &Agent{
		blockDNS:          false,
		allowedDomains:    make(map[string]bool),
		allowedIps:        make(map[string]bool),
		allowedDNSServers: make(map[string]bool),
		firewall:          firewall,
	}
}

func (a *Agent) init(egressPolicy string, dnsPolicy string) error {

	fmt.Printf("Egress policy: %s\n", egressPolicy)
	fmt.Printf("DNS policy: %s\n", dnsPolicy)

	if egressPolicy == "block" {
		blocking = true
		fmt.Println("Blocking mode enabled")
	} else {
		fmt.Println("Audit mode enabled")
	}

	if blocking {
		if dnsPolicy == "allowed-domains-only" {
			a.blockDNS = true
			fmt.Println("DNS queries to unallowed domains will be blocked")
		}
	}

	err := a.loadAllowedIp("allowed_ips.txt")
	if err != nil {
		log.Fatalf("Loading IP allowlist: %v", err)
	}

	err = a.loadAllowedDomain("allowed_domains.txt")
	if err != nil {
		log.Fatalf("Loading domain allowlist: %v", err)
	}

	err = a.loadAllowedDNSServers()
	if err != nil {
		log.Fatalf("Loading DNS servers allowlist: %v", err)
	}

	err = a.addToFirewall(a.allowedIps, a.allowedCIDR)
	if err != nil {
		log.Fatalf("Error adding to nftables: %v", err)
	}
	return nil
}

// TODO: don't use input in files
func (a *Agent) loadAllowedDomain(filename string) error {

	fmt.Println("loading allowed domains")

	// loads default first
	for _, domain := range defaultDomains {
		a.allowedDomains[domain] = true
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
		a.allowedDomains[line] = true
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// TODO: don't use input in files
func (a *Agent) loadAllowedIp(filename string) error {

	fmt.Println("loading allowed ips")

	// loads default first
	for _, ip := range defaultIps {
		a.allowedIps[ip] = true
		a.addIpToLogs("allowed", "unknown", ip)
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
			a.allowedCIDR = append(a.allowedCIDR, cidr)
		} else {
			fmt.Printf("error parsing CIDR: %v\n", err)
			a.allowedIps[line] = true
			a.addIpToLogs("allowed", "unknown", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (a *Agent) addToFirewall(ips map[string]bool, cidr []*net.IPNet) error {
	if !blocking {
		return nil
	}
	for ip := range ips {
		err := a.firewall.AddIp(ip)
		if err != nil {
			return fmt.Errorf("Error adding %s to firewall: %v\n", ip, err)
		}
	}
	for _, c := range cidr {
		err := a.firewall.AddIp(c.String())
		if err != nil {
			return fmt.Errorf("Error adding %s to firewall: %v\n", c.String(), err)
		}
	}
	return nil
}

func (a *Agent) isDomainAllowed(domain string) bool {
	if a.allowedDomains[domain] {
		return true
	}
	for allowedDomain := range a.allowedDomains {
		match, _ := path.Match(allowedDomain, domain)
		if match {
			return true
		}
	}
	return false
}

func (a *Agent) isIpAllowed(ipStr string) bool {
	if a.allowedIps[ipStr] {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Printf("Failed to parse IP: %s\n", ipStr)
		return false
	}
	for _, cidr := range a.allowedCIDR {
		if cidr.Contains(ip) {
			a.allowedIps[ipStr] = true
			return true
		}
	}
	return false
}

// TODO: move to a separate struct with an interface
func (a *Agent) addIpToLogs(decision string, domain string, ip string) {
	a.decisionLogsMutex.Lock()
	defer a.decisionLogsMutex.Unlock()

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

// TODO: move to a separate struct with an interface
func (a *Agent) getDNSServer() (string, error) {
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

func (a *Agent) loadAllowedDNSServers() error {
	for _, dns := range defaultDNSServers {
		a.allowedDNSServers[dns] = true
	}

	dnsServer, err := a.getDNSServer()
	if err != nil {
		return err
	}
	fmt.Printf("DNS Server: %s\n", dnsServer)
	a.allowedDNSServers[dnsServer] = true

	return nil
}

func (a *Agent) getDestinationIP(packet gopacket.Packet) (string, error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
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

func (a *Agent) processDNSQuery(packet gopacket.Packet) uint8 {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dns, _ := dnsLayer.(*layers.DNS)
	for _, q := range dns.Questions {
		domain := string(q.Name)
		fmt.Printf("DNS Question: %s %s\n", q.Name, q.Type)
		fmt.Print(domain)

		// making sure the DNS query is using a trusted DNS server
		destinationIP, err := a.getDestinationIP(packet)
		if err != nil {
			fmt.Println("Failed to get destination IP")
			a.addIpToLogs("blocked", domain, "unknown")
			return DROP_REQUEST
		}
		if !a.allowedDNSServers[destinationIP] {
			fmt.Printf("-> Blocked DNS Query. Untrusted DNS server %s\n", destinationIP)
			a.addIpToLogs("blocked", domain, "unknown")
			return DROP_REQUEST
		}

		if a.isDomainAllowed(domain) {
			fmt.Println("-> Allowed DNS Query")
			return ACCEPT_REQUEST
		}
		fmt.Println("-> Blocked DNS Query")
		a.addIpToLogs("blocked", domain, "unknown")
		return DROP_REQUEST
	}
	return DROP_REQUEST
}

func (a *Agent) processDNSTypeAResponse(domain string, answer *layers.DNSResourceRecord) {
	fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, answer.IP)
	fmt.Printf("%s:%s", answer.Name, answer.IP)
	ip := answer.IP.String()
	if a.isDomainAllowed(domain) {
		fmt.Println("-> Allowed request")
		if !a.allowedIps[ip] {
			err := a.firewall.AddIp(ip)
			a.addIpToLogs("allowed", domain, ip)
			if err != nil {
				fmt.Printf("failed to add %s to NFT tables", ip)
			} else {
				a.allowedIps[ip] = true
			}
		}
	} else if a.isIpAllowed(ip) {
		fmt.Println("-> Allowed request")
		a.addIpToLogs("allowed", domain, ip)
	} else {
		a.addIpToLogs("blocked", domain, ip)
		if blocking {
			fmt.Println("-> Blocked request")
		} else {
			fmt.Println("-> Unallowed request")
		}
	}
}

func (a *Agent) processDNSTypeCNAMEResponse(domain string, answer *layers.DNSResourceRecord) {
	cnameDomain := string(answer.CNAME)
	fmt.Printf("DNS Answer: %s %s %s\n", answer.Name, answer.Type, cnameDomain)
	fmt.Printf("%s:%s", answer.Name, cnameDomain)
	if a.isDomainAllowed(domain) {
		fmt.Println("-> Allowed request")
		if !a.allowedDomains[cnameDomain] {
			fmt.Printf("Adding %s to the allowed domains list\n", cnameDomain)
			a.allowedDomains[cnameDomain] = true
		}
	}
}

func (a *Agent) processDNSResponse(packet gopacket.Packet) uint8 {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dns, _ := dnsLayer.(*layers.DNS)
	domain := string(dns.Questions[0].Name)
	for _, answer := range dns.Answers {
		if answer.Type == layers.DNSTypeA {
			a.processDNSTypeAResponse(domain, &answer)
		} else if answer.Type == layers.DNSTypeCNAME {
			a.processDNSTypeCNAMEResponse(domain, &answer)
		}
	}
	return ACCEPT_REQUEST
}

// TODO: split this function
func (a *Agent) processPacket(packet gopacket.Packet) uint8 {
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
		if a.blockDNS && !dns.QR {
			return a.processDNSQuery(packet)
		} else if dns.QR {
			return a.processDNSResponse(packet)
		}
	}
	return ACCEPT_REQUEST
}
