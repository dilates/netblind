package rules

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"

	"github.com/dilates/netblind/resolver"
)

// Manager manages nftables rules for the netblind table/chain.
type Manager struct {
	mu      sync.Mutex
	handles map[string]string // appPath → nft rule handle
}

// NewManager creates a new nftables rule manager.
func NewManager() *Manager {
	return &Manager{
		handles: make(map[string]string),
	}
}

// Init ensures the netblind table and output chain exist.
func (m *Manager) Init() error {
	cmds := [][]string{
		{"nft", "add", "table", "inet", "netblind"},
		{"nft", "add", "chain", "inet", "netblind", "output",
			`{ type filter hook output priority 0 ; policy accept ; }`},
	}
	for _, args := range cmds {
		if err := runNft(args...); err != nil {
			// Ignore "already exists" errors
			if !strings.Contains(err.Error(), "File exists") {
				return fmt.Errorf("nft init: %w", err)
			}
		}
	}
	return nil
}

// SetBlock adds drop rules for all running instances of an application using
// cgroupv2-based matching. If no running instances are found (e.g. on daemon
// restart before the app reconnects) no kernel rule is added; the DB-backed
// decision in the connection handler enforces the block for the next connection.
func (m *Manager) SetBlock(appPath, appName string) error {
	cgroups := resolver.FindProcessCgroups(appPath)
	if len(cgroups) == 0 {
		log.Printf("netblind: no running instances of %s found; block will be enforced on next connection", appName)
		return nil
	}
	var firstErr error
	for _, cg := range cgroups {
		if err := m.setBlockByCgroup(appPath, appName, cg); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SetBlockForConnection adds a drop rule scoped to the specific cgroupv2 path
// from a live connection. Called when a block decision is made for an active flow.
func (m *Manager) SetBlockForConnection(appPath, appName, cgroupV2 string) error {
	if cgroupV2 == "" {
		return m.SetBlock(appPath, appName)
	}
	return m.setBlockByCgroup(appPath, appName, cgroupV2)
}

// setBlockByCgroup adds a single cgroupv2-matched drop rule and tracks its handle.
func (m *Manager) setBlockByCgroup(appPath, appName, cgroupV2 string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.handles[appPath]; exists {
		return nil
	}

	// Strip leading slash; nftables cgroupv2 paths are relative to the cgroup root.
	cgPath := strings.TrimPrefix(cgroupV2, "/")
	level := len(strings.Split(cgPath, "/"))

	rule := fmt.Sprintf(
		`socket cgroupv2 level %d "%s" meta l4proto { tcp, udp } drop comment "netblind:%s"`,
		level, cgPath, sanitizeName(appName),
	)

	out, err := exec.Command("nft", "--handle", "--echo",
		"add", "rule", "inet", "netblind", "output", rule).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft add rule for %s (cgroup %s): %w (output: %s)",
			appName, cgroupV2, err, string(out))
	}

	handle := extractHandle(string(out))
	if handle == "" {
		return fmt.Errorf("could not extract nft handle from: %s", string(out))
	}

	m.handles[appPath] = handle
	return nil
}

// RemoveBlock removes the nftables drop rule for the given application.
func (m *Manager) RemoveBlock(appPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	handle, ok := m.handles[appPath]
	if !ok {
		return nil // no rule to remove
	}

	if err := runNft("delete", "rule", "inet", "netblind", "output", "handle", handle); err != nil {
		return fmt.Errorf("nft delete rule handle %s: %w", handle, err)
	}

	delete(m.handles, appPath)
	return nil
}

// Flush removes all rules from the netblind output chain.
func (m *Manager) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	err := runNft("flush", "chain", "inet", "netblind", "output")
	m.handles = make(map[string]string)
	return err
}

// Teardown flushes the chain and then deletes the entire netblind table.
func (m *Manager) Teardown() error {
	_ = m.Flush()
	return runNft("delete", "table", "inet", "netblind")
}

// runNft executes an nft command with the given arguments.
func runNft(args ...string) error {
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %v: %w (output: %s)", args, err, string(out))
	}
	return nil
}

// extractHandle parses the handle number from nft --echo --handle output.
// nft prints: "add rule inet netblind output ... # handle 42"
func extractHandle(output string) string {
	const marker = "# handle "
	idx := strings.LastIndex(output, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(output[idx+len(marker):])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// sanitizeName removes characters unsafe for nft comments.
func sanitizeName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}
