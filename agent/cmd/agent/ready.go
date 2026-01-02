package main

import (
	"fmt"
	"os"
	"time"
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
