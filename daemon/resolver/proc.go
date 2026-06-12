package resolver

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Result holds resolved process information for a connection.
type Result struct {
	PID      int
	ExePath  string
	ExeName  string
	CgroupV2 string // cgroupv2 path, e.g. "/user.slice/user-1000.slice/session-2.scope"
}

// ResolveConnection finds the process owning the TCP/UDP connection on localPort.
// It retries up to 3 times with 15ms gaps to handle the /proc race condition where
// a new process hasn't yet registered its socket inode.
func ResolveConnection(proto string, localIP net.IP, localPort uint16) (*Result, error) {
	var result *Result
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(15 * time.Millisecond)
		}

		inode, err := findSocketInode(proto, localIP, localPort)
		if err != nil {
			lastErr = err
			continue
		}

		pid, err := findPIDForInode(inode)
		if err != nil {
			lastErr = err
			continue
		}

		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			lastErr = err
			continue
		}

		result = &Result{
			PID:      pid,
			ExePath:  exePath,
			ExeName:  filepath.Base(exePath),
			CgroupV2: ReadCgroupV2(pid),
		}
		return result, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("resolve connection (3 attempts): %w", lastErr)
	}
	return nil, fmt.Errorf("could not resolve connection after 3 attempts")
}

// ReadCgroupV2 reads the cgroupv2 hierarchy path for pid from /proc/<pid>/cgroup.
// Returns the path (e.g. "/user.slice/user-1000.slice/session-2.scope") or "".
func ReadCgroupV2(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		}
	}
	return ""
}

// FindProcessCgroups returns the distinct cgroupv2 paths for all running
// processes whose executable path equals appPath.
func FindProcessCgroups(appPath string) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var cgroups []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || exe != appPath {
			continue
		}
		cg := ReadCgroupV2(pid)
		if cg == "" {
			continue
		}
		if _, ok := seen[cg]; !ok {
			seen[cg] = struct{}{}
			cgroups = append(cgroups, cg)
		}
	}
	return cgroups
}

// findSocketInode parses /proc/net/{tcp,tcp6,udp,udp6} to find the inode
// for the socket listening on localPort at localIP.
func findSocketInode(proto string, localIP net.IP, localPort uint16) (string, error) {
	var procFiles []string
	switch strings.ToLower(proto) {
	case "tcp":
		procFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	case "udp":
		procFiles = []string{"/proc/net/udp", "/proc/net/udp6"}
	default:
		procFiles = []string{
			"/proc/net/tcp", "/proc/net/tcp6",
			"/proc/net/udp", "/proc/net/udp6",
		}
	}

	portHex := fmt.Sprintf("%04X", localPort)

	for _, path := range procFiles {
		inode, err := scanProcNetFile(path, portHex)
		if err != nil {
			continue
		}
		if inode != "" {
			return inode, nil
		}
	}

	return "", fmt.Errorf("inode not found for port %d", localPort)
}

// scanProcNetFile parses a single /proc/net/* file looking for portHex in the local address field.
func scanProcNetFile(path, portHex string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Fields: sl local_address rem_address st tx_queue rx_queue ... inode
		if len(fields) < 10 {
			continue
		}
		localAddr := fields[1]
		// local_address is "XXXXXXXX:PPPP" (hex ip:hex port)
		parts := strings.SplitN(localAddr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[1], portHex) {
			return fields[9], nil // inode field
		}
	}
	return "", scanner.Err()
}

// findPIDForInode walks /proc/<pid>/fd to find which process owns the given socket inode.
func findPIDForInode(inode string) (int, error) {
	target := fmt.Sprintf("socket:[%s]", inode)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission error or process exited
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("no process owns inode %s", inode)
}
