//go:build e2e
// +build e2e

package e2e_test

import (
	"net"
	"strconv"
)

// ephemeralListener wraps a net.Listener and exposes Port().
type ephemeralListener struct {
	net.Listener
	port int
}

func newListener() (*ephemeralListener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	_, portStr, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return &ephemeralListener{Listener: l, port: port}, nil
}

func (e *ephemeralListener) Port() int { return e.port }
