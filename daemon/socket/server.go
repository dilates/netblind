package socket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// rpcRequest is an incoming JSON-RPC 2.0 request.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

// rpcResponse is an outgoing JSON-RPC 2.0 response.
type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// rpcError represents a JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RuleEntry is the JSON-serialisable view of a rule sent to clients.
type RuleEntry struct {
	AppPath string `json:"app_path"`
	AppName string `json:"app_name"`
	Action  string `json:"action"`
}

// ConnEntry is the JSON-serialisable view of a live connection sent to clients.
type ConnEntry struct {
	Proto   string `json:"proto"`
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
	AppPath string `json:"app_path"`
	AppName string `json:"app_name"`
	Action  string `json:"action"`
	TS      string `json:"ts"`
}

// Handler exposes the daemon's state and control surface to RPC clients.
type Handler struct {
	mu          sync.RWMutex
	rules       map[string]RuleEntry
	connections []ConnEntry
	setRuleFn   func(appPath, action string) error
	deleteRuleFn func(appPath string) error
	getLogFn    func(limit int) ([]interface{}, error)
	statsFn     func() (int, int, int, int)
}

// NewHandler creates a new RPC handler with the provided callbacks.
func NewHandler(
	setRule func(appPath, action string) error,
	deleteRule func(appPath string) error,
	getLog func(limit int) ([]interface{}, error),
	stats func() (int, int, int, int),
) *Handler {
	return &Handler{
		rules:        make(map[string]RuleEntry),
		setRuleFn:    setRule,
		deleteRuleFn: deleteRule,
		getLogFn:     getLog,
		statsFn:      stats,
	}
}

// UpdateRule adds or replaces a rule in the in-memory cache.
func (h *Handler) UpdateRule(appPath, appName, action string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rules[appPath] = RuleEntry{AppPath: appPath, AppName: appName, Action: action}
}

// RemoveRule deletes a rule from the in-memory cache.
func (h *Handler) RemoveRule(appPath string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.rules, appPath)
}

// AddConnection appends a connection to the live list, capping at 500.
func (h *Handler) AddConnection(proto, srcIP string, srcPort uint16,
	dstIP string, dstPort uint16, appPath, appName, action string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.connections = append(h.connections, ConnEntry{
		Proto: proto, SrcIP: srcIP, SrcPort: srcPort,
		DstIP: dstIP, DstPort: dstPort, AppPath: appPath, AppName: appName,
		Action: action, TS: time.Now().UTC().Format(time.RFC3339),
	})
	if len(h.connections) > 500 {
		h.connections = h.connections[len(h.connections)-500:]
	}
}

// Server listens on a Unix socket and dispatches JSON-RPC requests.
type Server struct {
	socketPath string
	handler    *Handler
}

// NewServer creates a new JSON-RPC Unix socket server.
func NewServer(socketPath string, handler *Handler) *Server {
	return &Server{socketPath: socketPath, handler: handler}
}

// Run starts the Unix socket listener and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove old socket: %w", err)
	}

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", s.socketPath, err)
	}
	defer ln.Close()

	if err := os.Chmod(s.socketPath, 0666); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("socket accept: %v", err)
				continue
			}
		}
		go s.handleConn(conn)
	}
}

// handleConn reads JSON-RPC requests from a client connection and writes responses.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if err != io.EOF {
				log.Printf("rpc decode: %v", err)
			}
			return
		}

		resp := s.dispatch(&req)
		if err := enc.Encode(resp); err != nil {
			log.Printf("rpc encode: %v", err)
			return
		}
	}
}

// dispatch routes a request to the appropriate handler method.
func (s *Server) dispatch(req *rpcRequest) *rpcResponse {
	h := s.handler
	base := &rpcResponse{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "ping":
		base.Result = map[string]string{"status": "ok", "version": "1.0.0"}

	case "get_connections":
		h.mu.RLock()
		conns := make([]ConnEntry, len(h.connections))
		copy(conns, h.connections)
		h.mu.RUnlock()
		base.Result = conns

	case "get_rules":
		h.mu.RLock()
		rulesSlice := make([]RuleEntry, 0, len(h.rules))
		for _, r := range h.rules {
			rulesSlice = append(rulesSlice, r)
		}
		h.mu.RUnlock()
		base.Result = rulesSlice

	case "set_rule":
		var params struct {
			AppPath string `json:"app_path"`
			Action  string `json:"action"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			base.Error = &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
			return base
		}
		if err := h.setRuleFn(params.AppPath, params.Action); err != nil {
			base.Error = &rpcError{Code: -32000, Message: err.Error()}
			return base
		}
		base.Result = map[string]bool{"ok": true}

	case "delete_rule":
		var params struct {
			AppPath string `json:"app_path"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			base.Error = &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
			return base
		}
		if err := h.deleteRuleFn(params.AppPath); err != nil {
			base.Error = &rpcError{Code: -32000, Message: err.Error()}
			return base
		}
		base.Result = map[string]bool{"ok": true}

	case "get_log":
		var params struct {
			Limit int `json:"limit"`
		}
		if req.Params != nil {
			_ = json.Unmarshal(req.Params, &params)
		}
		if params.Limit <= 0 {
			params.Limit = 100
		}
		entries, err := h.getLogFn(params.Limit)
		if err != nil {
			base.Error = &rpcError{Code: -32000, Message: err.Error()}
			return base
		}
		base.Result = entries

	case "get_stats":
		total, blocked, allowed, apps := h.statsFn()
		base.Result = map[string]int{
			"total_connections": total,
			"blocked_today":     blocked,
			"allowed_today":     allowed,
			"apps_count":        apps,
		}

	default:
		base.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}

	return base
}
