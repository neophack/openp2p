package openp2p

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"strconv"
	"strings"
	"testing"
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

// --- Tests ---

func TestCGOCompatibility(t *testing.T) {
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
}
