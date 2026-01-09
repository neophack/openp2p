package openp2p

/*
#cgo LDFLAGS: -lws2_32
#include <stdlib.h>
#include "nat_c.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func natDetectTCP(serverHost string, serverPort int, lp int) (publicIP string, publicPort int, localPort int, err error) {
	gLog.dev("natDetectTCP start (CGO)")
	defer gLog.dev("natDetectTCP end (CGO)")

	cHost := C.CString(serverHost)
	defer C.free(unsafe.Pointer(cHost))

	bufSize := 1024
	cBuf := C.malloc(C.size_t(bufSize))
	defer C.free(cBuf)

	var bytesRead C.int

	ret := C.nat_detect_tcp_c(cHost, C.int(serverPort), C.int(lp), cBuf, C.int(bufSize), &bytesRead)
	if ret != 0 {
		return "", 0, 0, fmt.Errorf("nat_detect_tcp_c failed with code %d", ret)
	}

	nRead := int(bytesRead)
	buffer := C.GoBytes(cBuf, bytesRead)
	localPort = lp // C.nat_detect_tcp_c used lp

	response := strings.Split(string(buffer[:nRead]), ":")
	if len(response) < 2 {
		return "", 0, 0, fmt.Errorf("invalid response format: %s", string(buffer[:nRead]))
	}

	publicIP = response[0]
	port, err := strconv.Atoi(response[1])
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid port format: %w", err)
	}
	publicPort = port

	return
}

func natDetectUDP(serverHost string, serverPort int, localPort int) (publicIP string, publicPort int, err error) {
	gLog.dev("natDetectUDP start (CGO)")
	defer gLog.dev("natDetectUDP end (CGO)")

	cHost := C.CString(serverHost)
	defer C.free(unsafe.Pointer(cHost))

	// Construct message
	msg, err := newMessage(MsgNATDetect, MsgNAT, nil)
	if err != nil {
		return "", 0, err
	}

	// Prepare C buffers
	bufSize := 2048
	cBuf := C.malloc(C.size_t(bufSize))
	defer C.free(cBuf)

	var bytesRead C.int

	// Call C function
	ret := C.nat_detect_udp_c(cHost, C.int(serverPort), C.int(localPort),
		unsafe.Pointer(&msg[0]), C.int(len(msg)),
		cBuf, C.int(bufSize), &bytesRead)

	if ret != 0 {
		gLog.e("C.nat_detect_udp_c error code: %d", ret)
		return "", 0, fmt.Errorf("nat_detect_udp_c failed with code %d", ret)
	}

	// Parse response
	nRead := int(bytesRead)
	buffer := C.GoBytes(cBuf, bytesRead)

	natRsp := NatDetectRsp{}
	err = json.Unmarshal(buffer[openP2PHeaderSize:nRead], &natRsp)
	if err != nil {
		gLog.e("NAT detect unmarshal error:%s", err)
		return "", 0, err
	}

	return natRsp.IP, natRsp.Port, nil
}

func getNATType(host string, detectPort1 int, detectPort2 int) (publicIP string, NATType int, err error) {
	setUPNP(gConf.Network.PublicIPPort)
	// the random local port may be used by other.
	localPort := int(rand.Uint32()%15000 + 50000)

	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	var cIP [64]C.char
	var cNATType C.int

	ret := C.get_nat_type_c(cHost, C.int(detectPort1), C.int(detectPort2), C.int(localPort), &cIP[0], &cNATType)
	if ret != 0 {
		return "", 0, fmt.Errorf("get_nat_type_c failed with code %d", ret)
	}

	publicIP = C.GoString(&cIP[0])
	NATType = int(cNATType)
	return publicIP, NATType, nil
}

func parseNatRsp(buf []byte) (string, int, error) {
	if len(buf) == 0 {
		return "", 0, fmt.Errorf("empty buffer")
	}
	var cIP [64]C.char
	var cPort C.int
	ret := C.parse_nat_rsp_c((*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)), &cIP[0], &cPort)
	if ret != 0 {
		return "", 0, fmt.Errorf("parse_nat_rsp_c failed with code %d", ret)
	}
	return C.GoString(&cIP[0]), int(cPort), nil
}

func publicIPTest(publicIP string, echoPort int) (hasPublicIP int, hasUPNPorNATPMP int) {
	if publicIP == "" || echoPort == 0 {
		return
	}
	var echoConn *net.UDPConn
	gLog.d("echo server start")
	var err error
	echoConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: echoPort})
	if err != nil { // listen error
		gLog.e("echo server listen error:%s", err)
		return
	}
	defer echoConn.Close()
	// testing for public ip
	for i := 0; i < 2; i++ {
		if i == 1 {
			// test upnp or nat-pmp
			gLog.d("upnp test start")
			// 7 days for udp connection
			// 7 days for tcp connection
			setUPNP(echoPort)
		}
		gLog.d("public ip test start %s:%d", publicIP, echoPort)
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			break
		}
		defer conn.Close()
		dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", gConf.Network.ServerIP, gConf.Network.ServerPort))
		if err != nil {
			break
		}

		// The connection can write data to the desired address.
		msg, _ := newMessage(MsgNATDetect, MsgPublicIP, NatDetectReq{EchoPort: echoPort})
		_, err = conn.WriteTo(msg, dst)
		if err != nil {
			continue
		}
		buf := make([]byte, 1600)

		// wait for echo testing
		echoConn.SetReadDeadline(time.Now().Add(PublicIPEchoTimeout))
		nRead, _, err := echoConn.ReadFromUDP(buf)
		if err != nil {
			gLog.d("publicIPTest echoConn read timeout:%s", err)
			continue
		}
		natRsp := NatDetectRsp{}
		err = json.Unmarshal(buf[openP2PHeaderSize:nRead], &natRsp)
		if err != nil {
			gLog.d("publicIPTest Unmarshal error:%s", err)
			continue
		}
		if natRsp.Port == echoPort {
			if i == 1 {
				gLog.d("UPNP or NAT-PMP:YES")
				hasUPNPorNATPMP = 1
			} else {
				gLog.d("public ip:YES")
				hasPublicIP = 1
			}
			break
		}
	}
	return
}

func setUPNP(echoPort int) {
	nat, err := Discover()
	if err != nil || nat == nil {
		gLog.d("could not perform UPNP discover:%s", err)
		return
	}
	ext, err := nat.GetExternalAddress()
	if err != nil {
		gLog.d("could not perform UPNP external address:%s", err)
		return
	}
	gLog.i("PublicIP:%v", ext)

	externalPort, err := nat.AddPortMapping("udp", echoPort, echoPort, "openp2p", 604800)
	if err != nil {
		gLog.d("could not add udp UPNP port mapping %d", externalPort)
		return
	} else {
		nat.AddPortMapping("tcp", echoPort, echoPort, "openp2p", 604800)
	}
}
