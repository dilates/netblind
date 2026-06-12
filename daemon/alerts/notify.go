package alerts

import (
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	notifyBusName    = "org.freedesktop.Notifications"
	notifyObjectPath = "/org/freedesktop/Notifications"
	notifyInterface  = "org.freedesktop.Notifications"

	alertTimeout = 30 * time.Second
)

// Decision represents a user's allow/block choice for a connection alert.
type Decision string

const (
	DecisionAllow = Decision("allow")
	DecisionBlock = Decision("block")
	DecisionAsk   = Decision("ask") // timeout or deferred
)

// Alerter sends desktop notifications and waits for the user's decision.
type Alerter struct {
	conn *dbus.Conn
}

// NewAlerter creates an Alerter, connecting to the session D-Bus.
func NewAlerter() (*Alerter, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect to session bus: %w", err)
	}
	return &Alerter{conn: conn}, nil
}

// Close releases the D-Bus connection.
func (a *Alerter) Close() {
	if a.conn != nil {
		a.conn.Close()
	}
}

// Ask sends a notification asking the user whether to allow or block the
// connection from appName to dstIP:dstPort. It waits up to 30 seconds for a
// response and returns DecisionAsk if the user does not respond in time.
func (a *Alerter) Ask(appName, dstIP string, dstPort uint16) Decision {
	body := fmt.Sprintf("%s wants to connect to %s:%d.\nAllow or block?",
		appName, dstIP, dstPort)

	actions := []string{"allow", "Allow", "block", "Block"}
	hints := map[string]dbus.Variant{
		"urgency": dbus.MakeVariant(byte(1)), // normal urgency
	}

	obj := a.conn.Object(notifyBusName, notifyObjectPath)
	call := obj.Call(notifyInterface+".Notify", 0,
		"netblind",       // app_name
		uint32(0),        // replaces_id
		"security-high",  // app_icon
		"netblind alert", // summary
		body,             // body
		actions,          // actions
		hints,            // hints
		int32(alertTimeout.Milliseconds()), // expire_timeout_ms
	)
	if call.Err != nil {
		// Fall back: send a simple notification without actions
		_ = a.sendSimple(appName, dstIP, dstPort)
		return DecisionAsk
	}

	var notifID uint32
	if err := call.Store(&notifID); err != nil {
		return DecisionAsk
	}

	// Listen for ActionInvoked signal
	sigCh := make(chan *dbus.Signal, 4)
	a.conn.Signal(sigCh)
	defer a.conn.RemoveSignal(sigCh)

	if err := a.conn.AddMatchSignal(
		dbus.WithMatchInterface(notifyInterface),
		dbus.WithMatchMember("ActionInvoked"),
	); err != nil {
		return DecisionAsk
	}

	timeout := time.NewTimer(alertTimeout)
	defer timeout.Stop()

	for {
		select {
		case sig, ok := <-sigCh:
			if !ok {
				return DecisionAsk
			}
			if sig.Name != notifyInterface+".ActionInvoked" {
				continue
			}
			if len(sig.Body) < 2 {
				continue
			}
			sigID, ok := sig.Body[0].(uint32)
			if !ok || sigID != notifID {
				continue
			}
			action, ok := sig.Body[1].(string)
			if !ok {
				continue
			}
			switch action {
			case "allow":
				return DecisionAllow
			case "block":
				return DecisionBlock
			}
		case <-timeout.C:
			return DecisionAsk
		}
	}
}

// sendSimple sends a notification without interactive action buttons.
func (a *Alerter) sendSimple(appName, dstIP string, dstPort uint16) error {
	body := fmt.Sprintf("%s is connecting to %s:%d — check netblind for details.",
		appName, dstIP, dstPort)

	obj := a.conn.Object(notifyBusName, notifyObjectPath)
	call := obj.Call(notifyInterface+".Notify", 0,
		"netblind",
		uint32(0),
		"security-high",
		"netblind: new connection",
		body,
		[]string{},
		map[string]dbus.Variant{},
		int32(10000),
	)
	return call.Err
}
