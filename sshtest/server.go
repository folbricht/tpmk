package sshtest

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// A Server is an SSH server listening on a random port on the loopback interface. This
// server can be used in tests for SSH clients.
type Server struct {
	Endpoint string
	Listener net.Listener
	Config   *ssh.ServerConfig

	// Handler for incoming sessions, NullHandler if nil
	Handler func(ssh.Channel, <-chan *ssh.Request)

	mu     sync.Mutex
	closed bool
}

// NewServer starts and return a new SSH server. The caller is responsible for calling Close() when done.
func NewServer(hostKey ssh.Signer) *Server {
	s := NewUnstartedServer()
	s.Config = &ssh.ServerConfig{NoClientAuth: true}
	s.Config.AddHostKey(hostKey)
	s.Start()
	return s
}

// NewUnstartedServer returns a new server with the default config but doesn't start it
// allowing the caller to change the config or add keys before starting the server.
func NewUnstartedServer() *Server {
	ln := newListener()
	return &Server{
		Listener: ln,
		Endpoint: ln.Addr().String(),
	}
}

// Start the SSH server
func (s *Server) Start() {
	if s.Config == nil {
		panic("sshtest: no server config defined")
	}
	go func() {
		for {
			serverConn, err := s.Listener.Accept()
			if err != nil {
				s.mu.Lock()
				if s.closed {
					s.mu.Unlock()
					return
				}
				s.mu.Unlock()
				continue
			}
			go func() {
				defer serverConn.Close()

				_, chans, reqs, err := ssh.NewServerConn(serverConn, s.Config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					ch, inReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					if s.Handler == nil {
						NullHandler(ch, inReqs)
						continue
					}
					s.Handler(ch, inReqs)
				}
			}()
		}
	}()
}

// Close stops the Server's listener
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.Listener.Close()
}

func newListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("sshtest: failed to listen on a port: %v", err))
		}
	}
	return l
}

// NullHandler is used in SSH servers to discard all incoming requests and respond with success (code 0).
func NullHandler(ch ssh.Channel, in <-chan *ssh.Request) {
	defer ch.Close()

	req, ok := <-in
	if !ok {
		return
	}
	req.Reply(true, nil)

	SendStatus(ch, 0)
}

// SendStatus replies with an exits-status message on the provided channel.
func SendStatus(ch ssh.Channel, code uint32) error {
	var statusMsg = struct {
		Status uint32
	}{
		Status: code,
	}
	_, err := ch.SendRequest("exit-status", false, ssh.Marshal(&statusMsg))
	return err
}
