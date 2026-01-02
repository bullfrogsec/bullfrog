package agent

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ContainerInfo holds container identification data
type ContainerInfo struct {
	ID      string // Container ID (short form)
	Name    string // Container name
	Image   string // Image name
	RootPID int    // Container's PID 1 from host perspective
}

// IDockerProvider abstracts Docker operations for testability
type IDockerProvider interface {
	// FindContainerByIP returns container info for an IP, or nil if not found
	FindContainerByIP(ip string) (*ContainerInfo, error)

	// GetProcessInContainer extracts process info from container's /proc
	GetProcessInContainer(container *ContainerInfo, srcIP, srcPort, protocol string) (
		pid int, processName, cmdLine, execPath string, err error)

	Close() error
}

// NullDockerProvider is a no-op implementation used when Docker is unavailable
type NullDockerProvider struct{}

func (n *NullDockerProvider) FindContainerByIP(ip string) (*ContainerInfo, error) {
	return nil, fmt.Errorf("Docker not available")
}

func (n *NullDockerProvider) GetProcessInContainer(container *ContainerInfo, srcIP, srcPort, protocol string) (
	int, string, string, string, error) {
	return 0, "", "", "", fmt.Errorf("Docker not available")
}

func (n *NullDockerProvider) Close() error {
	return nil
}

// cachedContainer holds cached container info with expiration
type cachedContainer struct {
	info      *ContainerInfo
	expiresAt time.Time
}

// containerIPCache provides thread-safe caching of IP-to-container mappings
type containerIPCache struct {
	mu      sync.RWMutex
	entries map[string]*cachedContainer
}

const cacheExpiry = 60 * time.Second

func newContainerIPCache() *containerIPCache {
	return &containerIPCache{
		entries: make(map[string]*cachedContainer),
	}
}

func (c *containerIPCache) get(ip string) (*ContainerInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, exists := c.entries[ip]
	if !exists {
		return nil, false
	}

	if time.Now().After(cached.expiresAt) {
		return nil, false
	}

	return cached.info, true
}

func (c *containerIPCache) set(ip string, info *ContainerInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = &cachedContainer{
		info:      info,
		expiresAt: time.Now().Add(cacheExpiry),
	}
}

// DockerProvider implements IDockerProvider using Docker SDK
type DockerProvider struct {
	client *client.Client
	cache  *containerIPCache
}

// NewDockerProvider creates a new Docker provider
func NewDockerProvider() (*DockerProvider, error) {
	// Check if Docker socket exists
	if _, err := os.Stat("/var/run/docker.sock"); os.IsNotExist(err) {
		return nil, fmt.Errorf("Docker socket not found: %w", err)
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = cli.Ping(ctx)
	if err != nil {
		cli.Close()
		return nil, fmt.Errorf("failed to ping Docker daemon: %w", err)
	}

	return &DockerProvider{
		client: cli,
		cache:  newContainerIPCache(),
	}, nil
}

func (d *DockerProvider) Close() error {
	if d.client != nil {
		return d.client.Close()
	}
	return nil
}

// FindContainerByIP finds a Docker container by IP address
func (d *DockerProvider) FindContainerByIP(ipStr string) (*ContainerInfo, error) {
	// Check cache first
	if cached, found := d.cache.get(ipStr); found {
		return cached, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	containers, err := d.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	for _, c := range containers {
		// Inspect container to get network settings
		inspect, err := d.client.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}

		// Check all networks the container is connected to
		for _, network := range inspect.NetworkSettings.Networks {
			if network.IPAddress == ipStr {
				containerInfo := &ContainerInfo{
					ID:      c.ID[:12], // Short ID
					Name:    strings.TrimPrefix(c.Names[0], "/"),
					Image:   c.Image,
					RootPID: inspect.State.Pid,
				}

				// Cache the result
				d.cache.set(ipStr, containerInfo)

				return containerInfo, nil
			}
		}
	}

	return nil, fmt.Errorf("no container found with IP %s", ipStr)
}

// GetProcessInContainer gets process info from within a container's network namespace
func (d *DockerProvider) GetProcessInContainer(container *ContainerInfo, srcIP, srcPort, protocol string) (
	int, string, string, string, error) {

	if container.RootPID == 0 {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("container not running")
	}

	// Get the container's network namespace ID
	containerNsPath := fmt.Sprintf("/proc/%d/ns/net", container.RootPID)
	containerNs, err := os.Readlink(containerNsPath)
	if err != nil {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("failed to read container network namespace: %w", err)
	}

	// Find all processes in the same network namespace
	pids, err := findProcessesInNamespace(containerNs)
	if err != nil {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("failed to find processes in namespace: %w", err)
	}

	// Convert IP:Port to hex format
	hexAddr, err := ipPortToHex(srcIP, srcPort)
	if err != nil {
		return 0, "unknown", "unknown", "unknown", fmt.Errorf("failed to convert address: %w", err)
	}

	// Determine IP version
	ipVersion := detectIPVersion(srcIP)

	// Try each process to find the matching socket
	for _, pid := range pids {
		// Read socket entries from this process's /proc/net/{tcp,udp}
		var filename string
		if ipVersion == 4 {
			filename = fmt.Sprintf("/proc/%d/net/%s", pid, protocol)
		} else {
			filename = fmt.Sprintf("/proc/%d/net/%s6", pid, protocol)
		}

		entries, err := readProcNetFileFromPath(filename)
		if err != nil {
			continue // This process might not have network info
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
			continue // Socket not found in this process
		}

		// Find the actual process that owns this socket
		ownerPID, err := findProcessByInodeInNamespace(pids, matchedInode)
		if err != nil {
			continue
		}

		// Get process details
		processName := readFileFromProc(fmt.Sprintf("/proc/%d/comm", ownerPID))
		cmdLine := readFileFromProc(fmt.Sprintf("/proc/%d/cmdline", ownerPID))
		cmdLine = strings.ReplaceAll(cmdLine, "\x00", " ")
		cmdLine = strings.TrimSpace(cmdLine)

		execPath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", ownerPID))
		if execPath == "" {
			execPath = "unknown"
		}

		return ownerPID, processName, cmdLine, execPath, nil
	}

	return 0, "unknown", "unknown", "unknown", fmt.Errorf("socket not found in container namespace")
}

// readProcNetFileFromPath reads socket entries from a specific path
func readProcNetFileFromPath(filename string) ([]SocketEntry, error) {
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
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		entries = append(entries, SocketEntry{
			LocalAddr:  fields[1],
			RemoteAddr: fields[2],
			State:      fields[3],
			Inode:      inode,
		})
	}

	return entries, scanner.Err()
}

// findProcessByInodeInContainer finds process by inode within container's /proc
func findProcessByInodeInContainer(containerProcPath string, inode uint64) (int, error) {
	entries, err := os.ReadDir(containerProcPath)
	if err != nil {
		return 0, err
	}

	inodeStr := fmt.Sprintf("socket:[%d]", inode)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("%s/%d/fd", containerProcPath, pid)
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdEntries {
			linkPath := filepath.Join(fdDir, fdEntry.Name())
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

// readFileInContainer reads a file from container's /proc (deprecated, use readFileFromProc)
func readFileInContainer(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// readFileFromProc reads a file from /proc filesystem
func readFileFromProc(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// findProcessesInNamespace finds all processes in the given network namespace
func findProcessesInNamespace(targetNs string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
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

		// Check if this process is in the target namespace
		nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
		ns, err := os.Readlink(nsPath)
		if err != nil {
			continue // Process may have exited or no permission
		}

		if ns == targetNs {
			pids = append(pids, pid)
		}
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("no processes found in namespace %s", targetNs)
	}

	return pids, nil
}

// findProcessByInodeInNamespace finds a process by inode within a set of PIDs
func findProcessByInodeInNamespace(pids []int, inode uint64) (int, error) {
	inodeStr := fmt.Sprintf("socket:[%d]", inode)

	for _, pid := range pids {
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // Process may have exited or no permission
		}

		for _, fdEntry := range fdEntries {
			linkPath := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			if target == inodeStr {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("no process found for inode %d in namespace", inode)
}

// isDockerIP checks if an IP belongs to common Docker network ranges
func isDockerIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	dockerNetworkBlock := "172.17.0.0/12"

	_, cidr, _ := net.ParseCIDR(dockerNetworkBlock)
	if cidr.Contains(ip) {
		return true
	}

	return false
}
