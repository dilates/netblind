package monitor

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/dilates/netblind/resolver"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
)

// Connection holds the details of an observed outbound connection.
type Connection struct {
	Proto    string
	SrcIP    net.IP
	SrcPort  uint16
	DstIP    net.IP
	DstPort  uint16
	PID      int
	AppPath  string
	AppName  string
	CgroupV2 string // cgroupv2 path for the process
}

// Handler is called for each new outbound connection and returns the
// action taken: "allow", "block", or "ask".
type Handler func(conn Connection) string

// Monitor subscribes to conntrack NEW events and dispatches each outbound
// TCP/UDP connection to the provided handler.
type Monitor struct {
	handler Handler
}

// New creates a new Monitor with the given connection handler.
func New(handler Handler) *Monitor {
	return &Monitor{handler: handler}
}

// Run starts the conntrack subscription loop. It blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}

	var once sync.Once
	closeConn := func() { once.Do(func() { c.Close() }) }
	defer closeConn()

	evCh := make(chan conntrack.Event, 64)
	errCh, err := c.Listen(evCh, 4, []netfilter.NetlinkGroup{
		netfilter.GroupCTNew,
	})
	if err != nil {
		return err
	}

	// Close the connection when ctx is cancelled to unblock the workers.
	go func() {
		<-ctx.Done()
		closeConn()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errCh:
			if !ok {
				return nil
			}
			if err != nil && ctx.Err() == nil {
				log.Printf("conntrack error: %v", err)
			}
			return err
		case ev, ok := <-evCh:
			if !ok {
				return nil
			}
			m.handleEvent(ev)
		}
	}
}

// handleEvent processes a single conntrack event.
func (m *Monitor) handleEvent(ev conntrack.Event) {
	if ev.Flow == nil {
		return
	}
	flow := ev.Flow

	var proto string
	switch flow.TupleOrig.Proto.Protocol {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	default:
		return
	}

	srcAddr := flow.TupleOrig.IP.SourceAddress
	dstAddr := flow.TupleOrig.IP.DestinationAddress
	srcPort := flow.TupleOrig.Proto.SourcePort
	dstPort := flow.TupleOrig.Proto.DestinationPort

	srcIP := net.IP(srcAddr.AsSlice())
	dstIP := net.IP(dstAddr.AsSlice())

	res, err := resolver.ResolveConnection(proto, srcIP, srcPort)
	if err != nil {
		log.Printf("resolve %s:%d → %s:%d: %v", srcAddr, srcPort, dstAddr, dstPort, err)
		return
	}

	m.handler(Connection{
		Proto:    proto,
		SrcIP:    srcIP,
		SrcPort:  srcPort,
		DstIP:    dstIP,
		DstPort:  dstPort,
		PID:      res.PID,
		AppPath:  res.ExePath,
		AppName:  res.ExeName,
		CgroupV2: res.CgroupV2,
	})
}
