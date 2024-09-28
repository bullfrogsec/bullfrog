package main

import (
	"fmt"
	"os/exec"
)

type INetInfoProvider interface {
	GetDNSServer() (string, error)
	FlushDNSCache() error
}

type LinuxNetInfoProvider struct {
}

func (l *LinuxNetInfoProvider) GetDNSServer() (string, error) {
	networkInterface, err := exec.Command("sh", "-c", "ip route | grep default | awk '{print $5}'").Output()
	if err != nil {
		fmt.Printf("Error getting default network interface: %s\n", err)
		return "", err
	}
	// remove new line of networkInterface
	networkInterface = networkInterface[:len(networkInterface)-1]
	fmt.Printf("Network interface: %s\n", networkInterface)

	cmd := fmt.Sprintf("resolvectl status %s | grep 'DNS Servers' | awk '{print $3}'", networkInterface)

	dnsServer, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Println("Error getting DNS server: ", err)
		return "", err
	}
	// remove new line of dnsServer
	dnsServer = dnsServer[:len(dnsServer)-1]
	fmt.Printf("DNS server: %s\n", dnsServer)
	return string(dnsServer), nil
}

func(l *LinuxNetInfoProvider) FlushDNSCache() error {
	_, err := exec.Command("sh", "-c", "resolvectl flush-caches").Output()
	if err != nil {
		fmt.Println("Error flushing DNS cache: ", err)
		return err
	}
	return nil
}
