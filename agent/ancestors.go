package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func getParentPid(pid int32) (int32, error) {
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	content, err := os.ReadFile(statFile)
	if err != nil {
		return 0, err
	}

	// The file content is a single line of space-separated values
	fields := strings.Fields(string(content))
	if len(fields) < 4 {
		return 0, fmt.Errorf("unexpected content in %s", statFile)
	}

	// Parse the 4th field into a int32
	ppid, err := strconv.ParseInt(fields[3], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PPID: %v", err)
	}

	return int32(ppid), nil // The 4th field is the PPID
}

func getAncestorProcesses(pid int32) ([]int32, error) {
	var ancestors []int32

	currentPid := pid
	for currentPid != 1 { // Root process usually has PID 1

		ancestors = append(ancestors, currentPid)

		parentPid, err := getParentPid(currentPid)
		if err != nil {
			return nil, err
		}
		currentPid = parentPid
	}

	return ancestors, nil
}
