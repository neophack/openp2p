package openp2p

/*
#include "ikcp.h"
#include <stdint.h>
#include <stdlib.h>

extern int go_kcp_output(char *buf, int len, ikcpcb *kcp, void *user);

static inline ikcpcb* kcp_create_with_callback(uint32_t conv, void *user) {
    ikcpcb *kcp = ikcp_create(conv, user);
    ikcp_setoutput(kcp, (int (*)(const char *, int, ikcpcb *, void *))go_kcp_output);
    return kcp;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"
)

type underlayKCP struct {
	kcp          *C.ikcpcb
	conn         *net.UDPConn
	remote       *net.UDPAddr
	writeMtx     *sync.Mutex
	kcpMtx       *sync.Mutex
	handle       cgo.Handle
	closeOnce    sync.Once
	die          chan struct{}
	readDeadline time.Time
	readBuf      chan []byte
}

func (conn *underlayKCP) Protocol() string {
	return "kcp"
}

func (conn *underlayKCP) ReadBuffer() (*openP2PHeader, []byte, error) {
	return DefaultReadBuffer(conn)
}

func (conn *underlayKCP) WriteBytes(mainType uint16, subType uint16, data []byte) error {
	return DefaultWriteBytes(conn, mainType, subType, data)
}

func (conn *underlayKCP) WriteBuffer(data []byte) error {
	return DefaultWriteBuffer(conn, data)
}

func (conn *underlayKCP) WriteMessage(mainType uint16, subType uint16, packet interface{}) error {
	return DefaultWriteMessage(conn, mainType, subType, packet)
}

func (conn *underlayKCP) Close() error {
	conn.closeOnce.Do(func() {
		close(conn.die)
		conn.kcpMtx.Lock()
		if conn.kcp != nil {
			C.ikcp_release(conn.kcp)
			conn.kcp = nil
		}
		conn.kcpMtx.Unlock()
		if conn.conn != nil {
			conn.conn.Close()
		}
		conn.handle.Delete()
	})
	return nil
}

func (conn *underlayKCP) WLock() {
	conn.writeMtx.Lock()
}

func (conn *underlayKCP) WUnlock() {
	conn.writeMtx.Unlock()
}

func (conn *underlayKCP) SetReadDeadline(t time.Time) error {
	conn.readDeadline = t
	return nil
}

func (conn *underlayKCP) SetWriteDeadline(t time.Time) error {
	if conn.conn != nil {
		return conn.conn.SetWriteDeadline(t)
	}
	return nil
}

func (conn *underlayKCP) RemoteAddr() net.Addr {
	return conn.remote
}

func (conn *underlayKCP) Read(p []byte) (n int, err error) {
	for {
		conn.kcpMtx.Lock()
		if conn.kcp == nil {
			conn.kcpMtx.Unlock()
			return 0, io.EOF
		}
		n = int(C.ikcp_recv(conn.kcp, (*C.char)(unsafe.Pointer(&p[0])), C.int(len(p))))
		conn.kcpMtx.Unlock()

		if n > 0 {
			return n, nil
		}
		if n == -1 { // EAGAIN
			// wait for more data
		} else if n < 0 {
			return 0, fmt.Errorf("ikcp_recv error: %d", n)
		}

		timeout := time.Until(conn.readDeadline)
		if !conn.readDeadline.IsZero() && timeout <= 0 {
			return 0, errors.New("read timeout")
		}

		select {
		case <-conn.die:
			return 0, io.EOF
		case <-conn.readBuf:
			// data might be available now
		case <-time.After(timeout):
			if !conn.readDeadline.IsZero() {
				return 0, errors.New("read timeout")
			}
		}
	}
}

func (conn *underlayKCP) Write(p []byte) (n int, err error) {
	conn.kcpMtx.Lock()
	defer conn.kcpMtx.Unlock()
	if conn.kcp == nil {
		return 0, io.EOF
	}
	res := C.ikcp_send(conn.kcp, (*C.char)(unsafe.Pointer(&p[0])), C.int(len(p)))
	if res < 0 {
		return 0, fmt.Errorf("ikcp_send error: %d", res)
	}
	C.ikcp_flush(conn.kcp)
	return len(p), nil
}

func (conn *underlayKCP) updateLoop() {
	ticker := time.NewTicker(time.Millisecond * 10)
	defer ticker.Stop()
	for {
		select {
		case <-conn.die:
			return
		case <-ticker.C:
			conn.kcpMtx.Lock()
			if conn.kcp != nil {
				C.ikcp_update(conn.kcp, C.IUINT32(time.Now().UnixNano()/1e6))
			}
			conn.kcpMtx.Unlock()
		}
	}
}

func (conn *underlayKCP) readLoop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-conn.die:
			return
		default:
			conn.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := conn.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			if conn.remote == nil {
				conn.remote = addr
			}
			conn.kcpMtx.Lock()
			if conn.kcp != nil {
				C.ikcp_input(conn.kcp, (*C.char)(unsafe.Pointer(&buf[0])), C.long(n))
			}
			conn.kcpMtx.Unlock()
			// notify Read
			select {
			case conn.readBuf <- nil:
			default:
			}
		}
	}
}

func (conn *underlayKCP) Accept() error {
	return nil
}

func (conn *underlayKCP) CloseListener() {
	conn.Close()
}

//export go_kcp_output
func go_kcp_output(buf *C.char, len C.int, kcp *C.ikcpcb, user unsafe.Pointer) C.int {
	handle := *(*cgo.Handle)(user)
	conn, ok := handle.Value().(*underlayKCP)
	if !ok {
		return -1
	}
	data := C.GoBytes(unsafe.Pointer(buf), len)
	if conn.remote == nil {
		return -1
	}
	_, err := conn.conn.WriteToUDP(data, conn.remote)
	if err != nil {
		return -1
	}
	return 0
}

func listenKCP(addr string, idleTimeout time.Duration) (*underlayKCP, error) {
	gLog.d("kcp listen on %s", addr)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	ul := &underlayKCP{
		conn:     conn,
		writeMtx: &sync.Mutex{},
		kcpMtx:   &sync.Mutex{},
		die:      make(chan struct{}),
		readBuf:  make(chan []byte, 1),
	}
	ul.handle = cgo.NewHandle(ul)
	ul.kcp = C.kcp_create_with_callback(0, unsafe.Pointer(&ul.handle))
	C.ikcp_nodelay(ul.kcp, 1, 10, 2, 1)
	C.ikcp_wndsize(ul.kcp, 512, 512)
	C.ikcp_setmtu(ul.kcp, 1350)

	go ul.updateLoop()
	go ul.readLoop()

	return ul, nil
}

func dialKCP(conn *net.UDPConn, remoteAddr *net.UDPAddr, idleTimeout time.Duration) (*underlayKCP, error) {
	ul := &underlayKCP{
		conn:     conn,
		remote:   remoteAddr,
		writeMtx: &sync.Mutex{},
		kcpMtx:   &sync.Mutex{},
		die:      make(chan struct{}),
		readBuf:  make(chan []byte, 1),
	}
	ul.handle = cgo.NewHandle(ul)
	ul.kcp = C.kcp_create_with_callback(0, unsafe.Pointer(&ul.handle))
	C.ikcp_nodelay(ul.kcp, 1, 10, 2, 1)
	C.ikcp_wndsize(ul.kcp, 512, 512)
	C.ikcp_setmtu(ul.kcp, 1350)

	go ul.updateLoop()
	go ul.readLoop()

	return ul, nil
}
