package openp2p

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc64"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- Original Go Implementations (Pre-CGO) ---

func goNodeNameToID(name string) uint64 {
	return crc64.Checksum([]byte(name), crc64.MakeTable(crc64.ISO))
}

func goEncodeHeader(mainType uint16, subType uint16, length uint32) []byte {
	head := openP2PHeader{
		length,
		mainType,
		subType,
	}
	headBuf := new(bytes.Buffer)
	binary.Write(headBuf, binary.LittleEndian, head)
	return headBuf.Bytes()
}

func goDecodeHeader(data []byte) (*openP2PHeader, error) {
	head := openP2PHeader{}
	rd := bytes.NewReader(data)
	err := binary.Read(rd, binary.LittleEndian, &head)
	if err != nil {
		return nil, err
	}
	return &head, nil
}

var goPaddingArray = [][]byte{
	{0},
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
	{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4},
	{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
	{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
	{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
	{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
	{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
	{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
	{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11},
	{12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
	{13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13},
	{14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14},
	{15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
	{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
}

func goPkcs7Padding(plainData []byte, dataLen, blockSize int) int {
	padLen := blockSize - dataLen%blockSize
	pPadding := plainData[dataLen : dataLen+padLen]

	copy(pPadding, goPaddingArray[padLen][:padLen])
	return padLen
}

func goPkcs7UnPadding(origData []byte, dataLen int) ([]byte, error) {
	unPadLen := int(origData[dataLen-1])
	if unPadLen <= 0 || unPadLen > 16 {
		return nil, fmt.Errorf("wrong pkcs7 padding head size:%d", unPadLen)
	}
	return origData[:(dataLen - unPadLen)], nil
}

func goEncryptBytes(key []byte, out, in []byte, plainLen int) ([]byte, error) {
	if len(key) == 0 {
		return in[:plainLen], nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, cbcIVBlock)
	total := goPkcs7Padding(in, plainLen, aes.BlockSize) + plainLen
	mode.CryptBlocks(out[:total], in[:total])
	return out[:total], nil
}

func goDecryptBytes(key []byte, out, in []byte, dataLen int) ([]byte, error) {
	if len(key) == 0 {
		return in[:dataLen], nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, cbcIVBlock)
	mode.CryptBlocks(out[:dataLen], in[:dataLen])
	return goPkcs7UnPadding(out, dataLen)
}

func goCompareVersion(v1, v2 string) int {
	if v1 == v2 {
		return EQUAL
	}
	v1Arr := strings.Split(v1, ".")
	v2Arr := strings.Split(v2, ".")
	for i, subVer := range v1Arr {
		if len(v2Arr) <= i {
			return GREATER
		}
		subv1, _ := strconv.Atoi(subVer)
		subv2, _ := strconv.Atoi(v2Arr[i])
		if subv1 > subv2 {
			return GREATER
		}
		if subv1 < subv2 {
			return LESS
		}
	}
	return LESS
}

func goCalculateChecksum(data []byte) uint16 {
	length := len(data)
	sum := uint32(0)

	// Calculate the sum of 16-bit words
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add the last byte (if odd length)
	if length%2 != 0 {
		sum += uint32(data[length-1])
	}

	// Fold 32-bit sum to 16 bits
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)

	return uint16(^sum)
}

func goCalcRetryTimeRelay(x float64) float64 {
	return 10 + math.Exp(0.8*(x-3.6))
}
func goCalcRetryTimeDirect(x float64) float64 {
	return 10 + math.Exp(2.8*(x-4))
}

func goMin(nums ...int32) int32 {
	if len(nums) == 0 {
		return 0
	}
	minVal := nums[0]
	for _, num := range nums[1:] {
		if num < minVal {
			minVal = num
		}
	}
	return minVal
}

func goSanitizeFileName(fileName string) string {
	validFileName := fileName
	invalidChars := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range invalidChars {
		validFileName = strings.ReplaceAll(validFileName, char, " ")
	}
	return validFileName
}

func goEncodePushHeader(from uint64, to uint64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, from)
	binary.Write(buf, binary.LittleEndian, to)
	return buf.Bytes()
}

func goDecodePushHeader(data []byte) (*PushHeader, error) {
	if len(data) < PushHeaderSize {
		return nil, fmt.Errorf("data too short")
	}
	head := PushHeader{}
	rd := bytes.NewReader(data)
	err := binary.Read(rd, binary.LittleEndian, &head)
	if err != nil {
		return nil, err
	}
	return &head, nil
}

func goEncodeOverlayHeader(id uint64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, id)
	return buf.Bytes()
}

func goDecodeOverlayHeader(data []byte) (*overlayHeader, error) {
	if len(data) < overlayHeaderSize {
		return nil, fmt.Errorf("data too short")
	}
	head := overlayHeader{}
	rd := bytes.NewReader(data)
	err := binary.Read(rd, binary.LittleEndian, &head.id)
	if err != nil {
		return nil, err
	}
	return &head, nil
}

func goParseNatRsp(buf []byte) (string, int, error) {
	natRsp := NatDetectRsp{}
	err := json.Unmarshal(buf, &natRsp)
	if err != nil {
		return "", 0, err
	}
	return natRsp.IP, natRsp.Port, nil
}

func goIsIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.To16() != nil && ip.To4() == nil
}

func goIsLocalhost(ipStr string) bool {
	if ipStr == "localhost" || ipStr == "127.0.0.1" || ipStr == "::1" {
		return true
	}
	return false
}

func goParseMajorVer(ver string) int {
	v1Arr := strings.Split(ver, ".")
	if len(v1Arr) > 0 {
		n, _ := strconv.ParseInt(v1Arr[0], 10, 32)
		return int(n)
	}
	return 0
}

// --- Tests ---

func TestCGOCompatibility(t *testing.T) {
	InitForUnitTest(LvDEBUG)
	t.Run("NodeNameToID", func(t *testing.T) {
		names := []string{"test-node", "node-12345678", "very-long-node-name-for-testing", ""}
		for _, name := range names {
			goID := goNodeNameToID(name)
			cgoID := NodeNameToID(name)
			if goID != cgoID {
				t.Errorf("NodeNameToID(%s) mismatch: go=%v, cgo=%v", name, goID, cgoID)
			}
		}
	})

	t.Run("HeaderEncoding", func(t *testing.T) {
		tests := []struct {
			mainType uint16
			subType  uint16
			dataLen  uint32
		}{
			{1, 2, 100},
			{0xFFFF, 0xEEEE, 0x12345678},
			{0, 0, 0},
		}
		for _, tt := range tests {
			goBuf := goEncodeHeader(tt.mainType, tt.subType, tt.dataLen)
			cgoBuf := encodeHeader(tt.mainType, tt.subType, tt.dataLen)
			if !bytes.Equal(goBuf, cgoBuf) {
				t.Errorf("encodeHeader(%v, %v, %v) mismatch:\ngo=%x\ncgo=%x", tt.mainType, tt.subType, tt.dataLen, goBuf, cgoBuf)
			}

			// Test Decoding
			goHead, _ := goDecodeHeader(cgoBuf)
			cgoHead, _ := decodeHeader(cgoBuf)
			if goHead.MainType != cgoHead.MainType || goHead.SubType != cgoHead.SubType || goHead.DataLen != cgoHead.DataLen {
				t.Errorf("decodeHeader mismatch for %v:\ngo=%+v\ncgo=%+v", tt, goHead, cgoHead)
			}
		}
	})

	t.Run("PushHeader", func(t *testing.T) {
		tests := []struct {
			from uint64
			to   uint64
		}{
			{1, 2},
			{0xFFFFFFFFFFFFFFFF, 0xEEEEEEEEEEEEEEEE},
			{0, 0},
			{1234567890, 9876543210},
		}
		for _, tt := range tests {
			goBuf := goEncodePushHeader(tt.from, tt.to)
			cgoBuf := encodePushHeader(tt.from, tt.to)
			if !bytes.Equal(goBuf, cgoBuf) {
				t.Errorf("encodePushHeader(%v, %v) mismatch:\ngo=%x\ncgo=%x", tt.from, tt.to, goBuf, cgoBuf)
			}

			// Test Decoding
			goHead, _ := goDecodePushHeader(cgoBuf)
			cgoHead, _ := decodePushHeader(cgoBuf)
			if goHead.From != cgoHead.From || goHead.To != cgoHead.To {
				t.Errorf("decodePushHeader mismatch for %v:\ngo=%+v\ncgo=%+v", tt, goHead, cgoHead)
			}
		}
	})

	t.Run("OverlayHeader", func(t *testing.T) {
		tests := []uint64{
			1,
			0xFFFFFFFFFFFFFFFF,
			0,
			1234567890,
		}
		for _, id := range tests {
			goBuf := goEncodeOverlayHeader(id)
			cgoBuf := encodeOverlayHeader(id)
			if !bytes.Equal(goBuf, cgoBuf) {
				t.Errorf("encodeOverlayHeader(%v) mismatch:\ngo=%x\ncgo=%x", id, goBuf, cgoBuf)
			}

			// Test Decoding
			goHead, _ := goDecodeOverlayHeader(cgoBuf)
			cgoHead, _ := decodeOverlayHeader(cgoBuf)
			if goHead.id != cgoHead.id {
				t.Errorf("decodeOverlayHeader mismatch for %v:\ngo=%+v\ncgo=%+v", id, goHead, cgoHead)
			}
		}
	})

	t.Run("ParseNatRsp", func(t *testing.T) {
		tests := []string{
			`{"IP":"1.2.3.4","port":1234}`,
			`{"IP":"192.168.1.1","port":54321}`,
			`{"IP":"240e:3b3:3000:1::1","port":8080}`,
		}
		for _, jsonStr := range tests {
			buf := []byte(jsonStr)
			goIP, goPort, _ := goParseNatRsp(buf)
			cgoIP, cgoPort, err := parseNatRsp(buf)
			if err != nil {
				t.Errorf("parseNatRsp failed: %v", err)
				continue
			}
			if goIP != cgoIP || goPort != cgoPort {
				t.Errorf("parseNatRsp mismatch for %s:\ngo=%s:%d\ncgo=%s:%d", jsonStr, goIP, goPort, cgoIP, cgoPort)
			}
		}
	})

	t.Run("PKCS7", func(t *testing.T) {
		blockSize := 16
		for i := 1; i < 32; i++ {
			data := make([]byte, i+blockSize)
			copy(data, bytes.Repeat([]byte{byte(i)}, i))

			// Test Padding
			goData := make([]byte, i+blockSize)
			copy(goData, data[:i])
			cgoData := make([]byte, i+blockSize)
			copy(cgoData, data[:i])

			goPad := goPkcs7Padding(goData, i, blockSize)
			cgoPad := pkcs7Padding(cgoData, i, blockSize)

			if goPad != cgoPad {
				t.Errorf("pkcs7Padding length mismatch for size %d: go=%d, cgo=%d", i, goPad, cgoPad)
			}
			if !bytes.Equal(goData[:i+goPad], cgoData[:i+cgoPad]) {
				t.Errorf("pkcs7Padding content mismatch for size %d", i)
			}

			// Test UnPadding
			goUnpad, _ := goPkcs7UnPadding(goData, i+goPad)
			cgoUnpad, _ := pkcs7UnPadding(cgoData, i+cgoPad)
			if !bytes.Equal(goUnpad, cgoUnpad) {
				t.Errorf("pkcs7UnPadding mismatch for size %d", i)
			}
		}
	})

	t.Run("AES-CBC", func(t *testing.T) {
		key := []byte("1234567890123456") // 16 bytes for AES-128
		fmt.Printf("\n%-10s | %-16s | %-16s | %-10s\n", "Size", "Encrypt Status", "Decrypt Status", "Result")
		fmt.Println(strings.Repeat("-", 60))
		for i := 1; i <= 64; i++ {
			plainText := make([]byte, i+16) // Enough space for padding
			for j := 0; j < i; j++ {
				plainText[j] = byte(j % 256)
			}

			encryptOutGo := make([]byte, i+16)
			encryptInGo := make([]byte, i+16)
			copy(encryptInGo, plainText[:i])

			encryptOutCgo := make([]byte, i+16)
			encryptInCgo := make([]byte, i+16)
			copy(encryptInCgo, plainText[:i])

			resGo, _ := goEncryptBytes(key, encryptOutGo, encryptInGo, i)
			resCgo, _ := encryptBytes(key, encryptOutCgo, encryptInCgo, i)

			encryptMatch := bytes.Equal(resGo, resCgo)
			if !encryptMatch {
				t.Errorf("encryptBytes mismatch for size %d", i)
			}

			// Decrypt and compare
			decryptOutGo := make([]byte, len(resGo))
			resDecGo, _ := goDecryptBytes(key, decryptOutGo, resGo, len(resGo))

			decryptOutCgo := make([]byte, len(resCgo))
			resDecCgo, _ := decryptBytes(key, decryptOutCgo, resCgo, len(resCgo))

			decryptMatch := bytes.Equal(resDecGo, resDecCgo) && bytes.Equal(resDecCgo, plainText[:i])
			if !decryptMatch {
				t.Errorf("decryptBytes mismatch for size %d", i)
			}

			if i%8 == 0 || i == 1 || i == 64 {
				status := "PASS"
				if !encryptMatch || !decryptMatch {
					status = "FAIL"
				}
				fmt.Printf("%-10d | %-16s | %-16s | %-10s\n", i, "OK", "OK", status)
			}
		}
		fmt.Println(strings.Repeat("-", 60))
	})

	t.Run("CompareVersion", func(t *testing.T) {
		versions := [][2]string{
			{"1.0.0", "1.0.0"},
			{"1.0.1", "1.0.0"},
			{"1.0.0", "1.0.1"},
			{"2.0.0", "1.9.9"},
			{"1.2.3.4", "1.2.3.4"},
			{"1.2.3.5", "1.2.3.4"},
			{"1.2.3", "1.2.3.4"},
		}
		for _, v := range versions {
			goRes := goCompareVersion(v[0], v[1])
			cgoRes := compareVersion(v[0], v[1])
			if goRes != cgoRes {
				t.Errorf("compareVersion(%s, %s) mismatch: go=%d, cgo=%d", v[0], v[1], goRes, cgoRes)
			}
		}
	})

	t.Run("CalculateChecksum", func(t *testing.T) {
		testData := [][]byte{
			{1, 2, 3, 4},
			{0xFF, 0xFF, 0x00, 0x01},
			{1, 2, 3}, // odd length
			make([]byte, 100),
		}
		for _, data := range testData {
			goSum := goCalculateChecksum(data)
			cgoSum := calculateChecksum(data)
			if goSum != cgoSum {
				t.Errorf("calculateChecksum mismatch for %x: go=%d, cgo=%d", data, goSum, cgoSum)
			}
		}
	})

	t.Run("RetryTime", func(t *testing.T) {
		for x := 0.0; x < 10.0; x += 0.5 {
			goRelay := goCalcRetryTimeRelay(x)
			cgoRelay := calcRetryTimeRelay(x)
			if math.Abs(goRelay-cgoRelay) > 1e-9 {
				t.Errorf("calcRetryTimeRelay(%f) mismatch: go=%f, cgo=%f", x, goRelay, cgoRelay)
			}

			goDirect := goCalcRetryTimeDirect(x)
			cgoDirect := calcRetryTimeDirect(x)
			if math.Abs(goDirect-cgoDirect) > 1e-9 {
				t.Errorf("calcRetryTimeDirect(%f) mismatch: go=%f, cgo=%f", x, goDirect, cgoDirect)
			}
		}
	})

	t.Run("Min", func(t *testing.T) {
		tests := [][]int32{
			{1, 2, 3, 4, 5},
			{5, 4, 3, 2, 1},
			{-1, -5, 0, 10},
			{42},
		}
		for _, tt := range tests {
			goRes := goMin(tt...)
			cgoRes := min(tt...)
			if goRes != cgoRes {
				t.Errorf("min(%v) mismatch: go=%d, cgo=%d", tt, goRes, cgoRes)
			}
		}
	})

	t.Run("SanitizeFileName", func(t *testing.T) {
		names := []string{
			"test.txt",
			"test/file.txt",
			"a\\b:c*d?e\"f<g>h|i",
			"",
		}
		for _, name := range names {
			goRes := goSanitizeFileName(name)
			cgoRes := sanitizeFileName(name)
			if goRes != cgoRes {
				t.Errorf("sanitizeFileName(%s) mismatch: go=%s, cgo=%s", name, goRes, cgoRes)
			}
		}
	})

	t.Run("AppConfig", func(t *testing.T) {
		config := &AppConfig{
			SrcPort:  1234,
			Protocol: "tcp",
			PeerNode: "testnode",
		}
		// Test ID
		id := config.ID()
		expectedID := uint64(1234 * 10)
		if id != expectedID {
			t.Errorf("AppConfig.ID mismatch: expected %d, got %d", expectedID, id)
		}

		config.SrcPort = 0
		id = config.ID()
		expectedID = goNodeNameToID("testnode")
		if id != expectedID {
			t.Errorf("AppConfig.ID (memapp) mismatch: expected %d, got %d", expectedID, id)
		}

		// Test LogPeerNode
		config.relayMode = "public"
		logName := config.LogPeerNode()
		expectedLogName := fmt.Sprintf("%d", expectedID)
		if logName != expectedLogName {
			t.Errorf("AppConfig.LogPeerNode (public) mismatch: expected %s, got %s", expectedLogName, logName)
		}

		config.relayMode = "private"
		logName = config.LogPeerNode()
		if logName != "testnode" {
			t.Errorf("AppConfig.LogPeerNode (private) mismatch: expected %s, got %s", "testnode", logName)
		}
	})

	t.Run("InetAtoN", func(t *testing.T) {
		ips := []string{"1.2.3.4", "192.168.1.1", "10.0.0.1/24"}
		for _, ip := range ips {
			goRes, _ := goInetAtoN(ip)
			cRes, _ := inetAtoN(ip)
			if goRes != cRes {
				t.Errorf("InetAtoN(%s) mismatch: go=%d, c=%d", ip, goRes, cRes)
			}
		}
	})

	t.Run("IsIPv6", func(t *testing.T) {
		ips := []string{"1.2.3.4", "240e:3b3:3000:1::1", "::1", "invalid"}
		for _, ip := range ips {
			if goIsIPv6(ip) != IsIPv6(ip) {
				t.Errorf("IsIPv6(%s) mismatch", ip)
			}
		}
	})

	t.Run("IsLocalhost", func(t *testing.T) {
		hosts := []string{"localhost", "127.0.0.1", "::1", "1.2.3.4", "google.com"}
		for _, host := range hosts {
			if goIsLocalhost(host) != IsLocalhost(host) {
				t.Errorf("IsLocalhost(%s) mismatch", host)
			}
		}
	})

	t.Run("ParseMajorVer", func(t *testing.T) {
		vers := []string{"1.2.3", "v2.0.1", "10", "invalid"}
		for _, v := range vers {
			if goParseMajorVer(v) != parseMajorVer(v) {
				t.Errorf("parseMajorVer(%s) mismatch: go=%d, cgo=%d", v, goParseMajorVer(v), parseMajorVer(v))
			}
		}
	})

	t.Run("KCP", func(t *testing.T) {
		// Create server
			server, err := listenKCP("127.0.0.1:0", 1234, time.Second*10)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			serverAddr := server.conn.LocalAddr().(*net.UDPAddr)

			// Create client
			clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				t.Fatal(err)
			}
			client, err := dialKCP(clientConn, serverAddr, 1234, time.Second*10)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()

		// Send data from client to server
		testData := []byte("hello kcp")
		_, err = client.Write(testData)
		if err != nil {
			t.Fatal(err)
		}

		// Read data on server
		buf := make([]byte, 1024)
		server.SetReadDeadline(time.Now().Add(time.Second * 5))
		n, err := server.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != string(testData) {
			t.Errorf("expected %s, got %s", string(testData), string(buf[:n]))
		}

		// Send data from server to client
		_, err = server.Write([]byte("hello client"))
		if err != nil {
			t.Fatal(err)
		}

		// Read data on client
		client.SetReadDeadline(time.Now().Add(time.Second * 5))
		n, err = client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "hello client" {
			t.Errorf("expected hello client, got %s", string(buf[:n]))
		}
	})
}

func goInetAtoN(ipstr string) (uint32, error) {
	i, _, err := net.ParseCIDR(ipstr)
	if err != nil {
		i = net.ParseIP(ipstr)
		if i == nil {
			return 0, err
		}
	}
	ret := big.NewInt(0)
	ret.SetBytes(i.To4())
	return uint32(ret.Int64()), nil
}

func TestRTTAndMovingAverage(t *testing.T) {
	t.Run("calcRTT", func(t *testing.T) {
		// Test first time (DefaultRtt = 1000)
		res := calcRTT(1000, 50)
		if res != 50 {
			t.Errorf("calcRTT(1000, 50) expected 50, got %d", res)
		}

		// Test moving average
		// (100 * (1 - 1/20) + 200 * (1/20)) = 100 * 19/20 + 200 * 1/20 = 95 + 10 = 105
		res = calcRTT(100, 200)
		if res != 105 {
			t.Errorf("calcRTT(100, 200) expected 105, got %d", res)
		}
	})

	t.Run("movingAverage", func(t *testing.T) {
		// (1000 * (1 - 0.1) + 2000 * 0.1) = 900 + 200 = 1100
		res := movingAverage(1000, 2000, 0.1)
		if res != 1100 {
			t.Errorf("movingAverage(1000, 2000, 0.1) expected 1100, got %d", res)
		}

		// (1000 * (1 - 0.5) + 2000 * 0.5) = 500 + 1000 = 1500
		res = movingAverage(1000, 2000, 0.5)
		if res != 1500 {
			t.Errorf("movingAverage(1000, 2000, 0.5) expected 1500, got %d", res)
		}
	})
}
