package agent

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// IProcProvider abstracts /proc filesystem operations for testability
type IProcProvider interface {
	// ReadProcNetFile reads /proc/net/{tcp,udp,tcp6,udp6}
	ReadProcNetFile(protocol string, ipVersion int) ([]SocketEntry, error)

	// FindProcessByInode scans /proc/[pid]/fd/ to find which process owns an inode
	FindProcessByInode(inode uint64) (int, error)

	// GetProcessName reads /proc/[pid]/comm
	GetProcessName(pid int) (string, error)

	// GetCommandLine reads /proc/[pid]/cmdline
	GetCommandLine(pid int) (string, error)

	// GetExecutablePath reads /proc/[pid]/exe symlink
	GetExecutablePath(pid int) (string, error)

	// GetProcesses returns list of PIDs in /proc
	GetProcesses() ([]int, error)
}

// LinuxProcProvider implements IProcProvider for real /proc filesystem
type LinuxProcProvider struct{}

func (p *LinuxProcProvider) ReadProcNetFile(protocol string, ipVersion int) ([]SocketEntry, error) {
	// Construct path: /proc/net/tcp, /proc/net/udp, /proc/net/tcp6, /proc/net/udp6
	var filename string
	if ipVersion == 4 {
		filename = fmt.Sprintf("/proc/net/%s", protocol)
	} else {
		filename = fmt.Sprintf("/proc/net/%s6", protocol)
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", filename, err)
	}
	defer file.Close()

	var entries []SocketEntry
	scanner := bufio.NewScanner(file)

	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseSocketLine(line)
		if err != nil {
			continue // Skip malformed lines
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func (p *LinuxProcProvider) GetProcesses() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func (p *LinuxProcProvider) FindProcessByInode(inode uint64) (int, error) {
	pids, err := p.GetProcesses()
	if err != nil {
		return 0, err
	}

	inodeStr := fmt.Sprintf("socket:[%d]", inode)

	for _, pid := range pids {
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // Process may have exited or no permission
		}

		for _, entry := range entries {
			linkPath := filepath.Join(fdDir, entry.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			if target == inodeStr {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("no process found for inode %d", inode)
}

func (p *LinuxProcProvider) GetProcessName(pid int) (string, error) {
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	data, err := os.ReadFile(commPath)
	if err != nil {
		return "", err
	}
	// Remove trailing newline
	return strings.TrimSpace(string(data)), nil
}

func (p *LinuxProcProvider) GetCommandLine(pid int) (string, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "", err
	}
	// Replace null bytes with spaces for readability
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmdline), nil
}

func (p *LinuxProcProvider) GetExecutablePath(pid int) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)
	if err != nil {
		return "", err
	}
	return target, nil
}

// parseSocketLine parses a line from /proc/net/{tcp,udp}
// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
// Example: "0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 966876 1 ..."
func parseSocketLine(line string) (SocketEntry, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return SocketEntry{}, fmt.Errorf("invalid line format")
	}

	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return SocketEntry{}, fmt.Errorf("invalid inode: %w", err)
	}

	return SocketEntry{
		LocalAddr:  fields[1],
		RemoteAddr: fields[2],
		State:      fields[3],
		Inode:      inode,
	}, nil
}

// ipPortToHex converts IP:Port to hex format used in /proc/net/*
// Example: "127.0.0.1:631" -> "0100007F:0277"
func ipPortToHex(ipStr string, portStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port: %s", portStr)
	}

	// Convert IPv4 to 4-byte representation
	if ip4 := ip.To4(); ip4 != nil {
		// /proc/net/tcp uses little-endian format for IP
		hexIP := fmt.Sprintf("%02X%02X%02X%02X", ip4[3], ip4[2], ip4[1], ip4[0])
		hexPort := fmt.Sprintf("%04X", port)
		return fmt.Sprintf("%s:%s", hexIP, hexPort), nil
	}

	// Convert IPv6 to 16-byte representation
	if ip16 := ip.To16(); ip16 != nil {
		// IPv6 in /proc/net/tcp6 is represented in groups of 4 bytes, little-endian
		var hexParts []string
		for i := 0; i < 16; i += 4 {
			part := fmt.Sprintf("%02X%02X%02X%02X", ip16[i+3], ip16[i+2], ip16[i+1], ip16[i])
			hexParts = append(hexParts, part)
		}
		hexIP := strings.Join(hexParts, "")
		hexPort := fmt.Sprintf("%04X", port)
		return fmt.Sprintf("%s:%s", hexIP, hexPort), nil
	}

	return "", fmt.Errorf("invalid IP format")
}

// detectIPVersion determines if IP is IPv4 or IPv6
func detectIPVersion(ipStr string) int {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 4 // default to IPv4
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// getProcessInfo is the main entry point for process lookup
// Returns: (PID, ProcessName, CommandLine, ExecutablePath, error)
func getProcessInfo(provider IProcProvider, srcIP, srcPort, protocol string) (int, string, string, string, error) {
	// Convert IP:Port to hex format
	hexAddr, err := ipPortToHex(srcIP, srcPort)
	if err != nil {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("failed to convert address: %w", err)
	}

	// Determine IP version (4 or 6)
	ipVersion := detectIPVersion(srcIP)

	// Read socket entries from /proc/net/{tcp,udp}
	entries, err := provider.ReadProcNetFile(protocol, ipVersion)
	if err != nil {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("failed to read /proc/net/%s: %w", protocol, err)
	}

	// Find matching socket by local address
	var matchedInode uint64
	for _, entry := range entries {
		if entry.LocalAddr == hexAddr {
			matchedInode = entry.Inode
			break
		}
	}

	if matchedInode == 0 {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("socket not found in /proc/net/%s", protocol)
	}

	// Find process owning this inode
	pid, err := provider.FindProcessByInode(matchedInode)
	if err != nil {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("failed to find process: %w", err)
	}

	// Get process name
	processName, err := provider.GetProcessName(pid)
	if err != nil {
		processName = "unknown"
	}

	// Get command line
	cmdLine, err := provider.GetCommandLine(pid)
	if err != nil {
		cmdLine = "unknown"
	}

	// Get executable path
	execPath, err := provider.GetExecutablePath(pid)
	if err != nil {
		execPath = "unknown"
	}

	return pid, processName, cmdLine, execPath, nil
}
