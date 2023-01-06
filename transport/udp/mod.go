package udp

import (
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"go.dedis.ch/cs438/transport"
)

const bufSize = 65000

// NewUDP returns a new udp transport implementation.
func NewUDP() transport.Transport {
	return &UDP{sendConns: make(map[string]net.Conn)}
}

// UDP implements a transport layer using UDP
//
// - implements transport.Transport
type UDP struct {
	sync.RWMutex
	transport.Transport
	sendConns map[string]net.Conn
}

// CreateSocket implements transport.Transport
func (n *UDP) CreateSocket(address string) (transport.ClosableSocket, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, xerrors.Errorf("failed to resolve udp address (%s) : %v", address, err)
	}

	ln, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, xerrors.Errorf("failed to listen to the given address (%s): %v", address, err)
	}

	return &Socket{
		UDP:     n,
		rcvConn: ln,
	}, nil
}

// Socket implements a network socket using UDP.
//
// - implements transport.Socket
// - implements transport.ClosableSocket
type Socket struct {
	transport.Socket
	transport.ClosableSocket
	*UDP
	rcvConn net.Conn
	ins     packets
	outs    packets
}

type packets struct {
	sync.Mutex
	data []transport.Packet
}

func (p *packets) add(pkt transport.Packet) {
	p.Lock()
	defer p.Unlock()

	p.data = append(p.data, pkt.Copy())
}

// Close implements transport.Socket. It returns an error if already closed.
func (s *Socket) Close() error {
	return s.rcvConn.Close()
}

// Send implements transport.Socket
func (s *Socket) Send(dest string, pkt transport.Packet, timeout time.Duration) error {
	s.Lock()
	_, ok := s.sendConns[dest]
	if !ok {
		newConn, err := net.Dial("udp", dest)
		if err != nil {
			s.Unlock()
			return xerrors.Errorf("failed to establish a new udp connection: %v", err)
		}
		s.sendConns[dest] = newConn
	}
	conn := s.sendConns[dest]
	s.Unlock()

	buf, err := pkt.Marshal()
	if err != nil {
		return xerrors.Errorf("failed to marshal packet: %v", err)
	}

	if timeout > 0 {
		err = conn.SetWriteDeadline(time.Now().Add(timeout))
		if err != nil {
			return xerrors.Errorf("failed to set a WriteDeadline: %v", err)
		}
	}

	_, err = conn.Write(buf)
	if err != nil {
		return xerrors.Errorf("failed to write buffer [%v]: %v", len(buf), err)
	}

	s.outs.add(pkt)
	return nil
}

// Recv implements transport.Socket. It blocks until a packet is received, or
// the timeout is reached. In the case the timeout is reached, return a
// TimeoutErr.
func (s *Socket) Recv(timeout time.Duration) (transport.Packet, error) {
	var newPkt transport.Packet

	if timeout > 0 {
		err := s.rcvConn.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return newPkt, xerrors.Errorf("failed to set a ReadDeadline: %v", err)
		}
	}

	buf := make([]byte, bufSize)

	nRead, err := s.rcvConn.Read(buf)
	if err != nil {
		if os.IsTimeout(err) {
			return newPkt, transport.TimeoutError(0)
		}
		return newPkt, err
	}

	err = newPkt.Unmarshal(buf[:nRead])
	if err != nil {
		return newPkt, xerrors.Errorf("failed to unmarshall packet: %v", err)
	}

	s.ins.add(newPkt)
	return newPkt, nil
}

// GetAddress implements transport.Socket. It returns the address assigned. Can
// be useful in the case one provided a :0 address, which makes the system use a
// random free port.
func (s *Socket) GetAddress() string {
	return s.rcvConn.LocalAddr().String()
}

// GetIns implements transport.Socket
func (s *Socket) GetIns() []transport.Packet {
	s.ins.Lock()
	defer s.ins.Unlock()
	return s.ins.data
}

// GetOuts implements transport.Socket
func (s *Socket) GetOuts() []transport.Packet {
	s.outs.Lock()
	defer s.outs.Unlock()
	return s.outs.data
}
