package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/dilates/netblind/alerts"
	"github.com/dilates/netblind/monitor"
	"github.com/dilates/netblind/rules"
	"github.com/dilates/netblind/socket"
	"github.com/dilates/netblind/store"
)

const version = "1.0.0"

func main() {
	socketPath := flag.String("socket", "/run/netblind.sock", "Unix socket path")
	dbPath := flag.String("db", "/var/lib/netblind/netblind.db", "SQLite database path")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn")
	flag.Parse()

	if *logLevel == "debug" {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	log.Printf("netblind daemon v%s starting", version)

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0750); err != nil {
		log.Fatalf("create db dir: %v", err)
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	nft := rules.NewManager()
	if err := nft.Init(); err != nil {
		log.Printf("nft init: %v (continuing without active blocking)", err)
	}

	alerter, err := alerts.NewAlerter()
	if err != nil {
		log.Printf("alerter init: %v (notifications disabled)", err)
	}
	if alerter != nil {
		defer alerter.Close()
	}

	// Restore all existing block rules into nftables.
	existingRules, err := db.GetAllRules()
	if err != nil {
		log.Printf("load rules: %v", err)
	}
	for _, r := range existingRules {
		if r.Action == "block" {
			if err := nft.SetBlock(r.AppPath, r.AppName); err != nil {
				log.Printf("restore block rule for %s: %v", r.AppName, err)
			}
		}
	}

	pending := newDecisionTracker()

	connHandler := func(conn monitor.Connection) string {
		rule, err := db.GetRule(conn.AppPath)
		if err != nil {
			log.Printf("get rule for %s: %v", conn.AppPath, err)
			return "ask"
		}

		action := "ask"
		if rule != nil {
			action = rule.Action
		}

		if action == "ask" || action == "" {
			// Only prompt once per app at a time.
			if pending.tryLock(conn.AppPath) {
				defer pending.unlock(conn.AppPath)

				decision := alerts.DecisionAsk
				if alerter != nil {
					decision = alerter.Ask(conn.AppName, conn.DstIP.String(), conn.DstPort)
				}

				switch decision {
				case alerts.DecisionAllow:
					action = "allow"
					_ = db.SetRule(conn.AppPath, conn.AppName, "allow")
				case alerts.DecisionBlock:
					action = "block"
					_ = db.SetRule(conn.AppPath, conn.AppName, "block")
					_ = nft.SetBlockForConnection(conn.AppPath, conn.AppName, conn.CgroupV2)
				default:
					action = "ask"
					_ = db.SetRule(conn.AppPath, conn.AppName, "ask")
				}
			}
		}

		_ = db.InsertLog(store.LogEntry{
			AppPath: conn.AppPath,
			AppName: conn.AppName,
			SrcIP:   conn.SrcIP.String(),
			SrcPort: int(conn.SrcPort),
			DstIP:   conn.DstIP.String(),
			DstPort: int(conn.DstPort),
			Proto:   conn.Proto,
			Action:  action,
		})

		return action
	}

	// Build RPC handler with callbacks into db and nft.
	var rpcHandler *socket.Handler
	rpcHandler = socket.NewHandler(
		func(appPath, action string) error {
			name := filepath.Base(appPath)
			allRules, _ := db.GetAllRules()
			for _, r := range allRules {
				if r.AppPath == appPath {
					name = r.AppName
					break
				}
			}
			if err := db.SetRule(appPath, name, action); err != nil {
				return err
			}
			if action == "block" {
				if err := nft.SetBlock(appPath, name); err != nil {
					return err
				}
			} else {
				_ = nft.RemoveBlock(appPath)
			}
			rpcHandler.UpdateRule(appPath, name, action)
			return nil
		},
		func(appPath string) error {
			if err := db.DeleteRule(appPath); err != nil {
				return err
			}
			_ = nft.RemoveBlock(appPath)
			rpcHandler.RemoveRule(appPath)
			return nil
		},
		func(limit int) ([]interface{}, error) {
			entries, err := db.GetRecentLog(limit)
			if err != nil {
				return nil, err
			}
			result := make([]interface{}, len(entries))
			for i, e := range entries {
				result[i] = e
			}
			return result, nil
		},
		func() (int, int, int, int) {
			allowed, blocked, err := db.CountTodayStats()
			if err != nil {
				log.Printf("stats: %v", err)
			}
			allRules, _ := db.GetAllRules()
			return allowed + blocked, blocked, allowed, len(allRules)
		},
	)

	for _, r := range existingRules {
		rpcHandler.UpdateRule(r.AppPath, r.AppName, r.Action)
	}

	wrappedHandler := func(conn monitor.Connection) string {
		action := connHandler(conn)
		rpcHandler.AddConnection(conn.Proto,
			conn.SrcIP.String(), conn.SrcPort,
			conn.DstIP.String(), conn.DstPort,
			conn.AppPath, conn.AppName, action)
		return action
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mon := monitor.New(wrappedHandler)
	go func() {
		if err := mon.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("conntrack monitor: %v", err)
		}
	}()

	srv := socket.NewServer(*socketPath, rpcHandler)
	go func() {
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("socket server: %v", err)
		}
	}()

	log.Printf("netblind daemon ready (socket=%s, db=%s)", *socketPath, *dbPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	log.Printf("shutting down...")
	cancel()

	if err := nft.Flush(); err != nil {
		log.Printf("nft flush: %v", err)
	}
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		log.Printf("remove socket: %v", err)
	}
	log.Printf("netblind daemon stopped")
}

// decisionTracker prevents duplicate alert prompts for the same app.
type decisionTracker struct {
	mu      sync.Mutex
	pending map[string]struct{}
}

func newDecisionTracker() *decisionTracker {
	return &decisionTracker{pending: make(map[string]struct{})}
}

func (t *decisionTracker) tryLock(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.pending[key]; ok {
		return false
	}
	t.pending[key] = struct{}{}
	return true
}

func (t *decisionTracker) unlock(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, key)
}
