package main

import (
	"fmt"
	"os/exec"
)

type IFirewall interface {
	AddIp(ip string) error
}

type NFTFirewall struct {
}

func (nft *NFTFirewall) AddIp(ip string) error {
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
