package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
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
// with event-driven invalidation to handle Docker IP reuse
type containerIPCache struct {
	mu sync.RWMutex
	// IP -> ContainerInfo (for fast lookups)
	entries map[string]*cachedContainer
	// ContainerID -> []IPs (for invalidation when container stops)
	containerIPs map[string][]string
}

const cacheExpiry = 30 * time.Second

func newContainerIPCache() *containerIPCache {
	return &containerIPCache{
		entries:      make(map[string]*cachedContainer),
		containerIPs: make(map[string][]string),
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

	// Track this IP under the container ID for invalidation
	containerID := info.ID
	if !c.ipInSlice(ip, c.containerIPs[containerID]) {
		c.containerIPs[containerID] = append(c.containerIPs[containerID], ip)
	}
}

// invalidateContainer removes all cache entries associated with a container ID
func (c *containerIPCache) invalidateContainer(containerID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get all IPs associated with this container
	ips, exists := c.containerIPs[containerID]
	if !exists {
		return
	}

	// Remove cache entries for all IPs
	for _, ip := range ips {
		delete(c.entries, ip)
	}

	// Remove the container tracking
	delete(c.containerIPs, containerID)
}

func (c *containerIPCache) ipInSlice(ip string, slice []string) bool {
	for _, item := range slice {
		if item == ip {
			return true
		}
	}
	return false
}

// DockerProvider implements IDockerProvider using Docker SDK
type DockerProvider struct {
	client       *client.Client
	cache        *containerIPCache
	eventCancel  context.CancelFunc
	eventStopped chan struct{}
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

	// Create provider with event monitoring
	eventCtx, eventCancel := context.WithCancel(context.Background())
	provider := &DockerProvider{
		client:       cli,
		cache:        newContainerIPCache(),
		eventCancel:  eventCancel,
		eventStopped: make(chan struct{}),
	}

	// Start event monitoring in background
	go provider.monitorDockerEvents(eventCtx)

	return provider, nil
}

func (d *DockerProvider) Close() error {
	// Stop event monitoring
	if d.eventCancel != nil {
		d.eventCancel()
		// Wait for event monitoring to stop (with timeout)
		select {
		case <-d.eventStopped:
		case <-time.After(2 * time.Second):
			log.Printf("Warning: Docker event monitoring did not stop within timeout")
		}
	}

	// Close Docker client
	if d.client != nil {
		return d.client.Close()
	}
	return nil
}

// monitorDockerEvents listens to Docker events and invalidates cache on container lifecycle changes
func (d *DockerProvider) monitorDockerEvents(ctx context.Context) {
	defer close(d.eventStopped)

	// Filter for container die, stop, and kill events
	eventFilters := filters.NewArgs()
	eventFilters.Add("type", "container")
	eventFilters.Add("event", "die")
	eventFilters.Add("event", "stop")
	eventFilters.Add("event", "kill")

	eventChan, errChan := d.client.Events(ctx, events.ListOptions{
		Filters: eventFilters,
	})

	log.Printf("Docker event monitoring started")

	for {
		select {
		case <-ctx.Done():
			log.Printf("Docker event monitoring stopped")
			return

		case err := <-errChan:
			if err != nil && err != io.EOF && ctx.Err() == nil {
				log.Printf("Docker event error: %v", err)
				// Reconnect after delay
				time.Sleep(5 * time.Second)
				if ctx.Err() != nil {
					return
				}
				eventChan, errChan = d.client.Events(ctx, events.ListOptions{
					Filters: eventFilters,
				})
			}

		case event := <-eventChan:
			// Extract container ID (short form)
			containerID := event.Actor.ID
			if len(containerID) > 12 {
				containerID = containerID[:12]
			}

			log.Printf("Container event: %s %s (invalidating cache)", event.Action, containerID)
			d.cache.invalidateContainer(containerID)
		}
	}
}

// FindContainerByIP finds a Docker container by IP address
// Includes retry logic to handle race conditions when containers are starting
func (d *DockerProvider) FindContainerByIP(ipStr string) (*ContainerInfo, error) {
	// Check cache first - invalidated automatically on container stop/die/kill events
	if cached, found := d.cache.get(ipStr); found {
		return cached, nil
	}

	// Retry logic for race conditions when containers are just starting up
	// Container network settings may not be immediately available in Docker API
	const maxRetries = 3
	const retryDelay = 50 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		containers, err := d.client.ContainerList(ctx, container.ListOptions{})
		cancel()

		if err != nil {
			lastErr = fmt.Errorf("failed to list containers: %w", err)
			continue
		}

		for _, c := range containers {
			// Inspect container to get network settings
			inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 1*time.Second)
			inspect, err := d.client.ContainerInspect(inspectCtx, c.ID)
			inspectCancel()

			if err != nil {
				continue
			}

			// Skip containers that aren't running yet
			if inspect.State == nil || !inspect.State.Running {
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

					// Cache the result - will be invalidated on container lifecycle events
					d.cache.set(ipStr, containerInfo)

					return containerInfo, nil
				}
			}
		}

		lastErr = fmt.Errorf("no container found with IP %s", ipStr)
	}

	return nil, lastErr
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
