package openp2p

/*
#include <stdlib.h>
#include "common_c.h"
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

const MinNodeNameLen = 8

func getmac(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	firstMac := ""
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if firstMac == "" {
				firstMac = iface.HardwareAddr.String()
			}
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.String() == ip {
				if iface.HardwareAddr.String() != "" {
					return iface.HardwareAddr.String()
				}
				return firstMac
			}
		}
	}
	return firstMac
}

var cbcIVBlock = []byte("UHNJUSBACIJFYSQN")

func pkcs7Padding(plainData []byte, dataLen, blockSize int) int {
	return int(C.pkcs7_padding_c((*C.uint8_t)(unsafe.Pointer(&plainData[0])), C.int(dataLen), C.int(blockSize)))
}

func pkcs7UnPadding(origData []byte, dataLen int) ([]byte, error) {
	padLen := int(C.pkcs7_unpadding_c((*C.uint8_t)(unsafe.Pointer(&origData[0])), C.int(dataLen)))
	if padLen < 0 {
		return nil, fmt.Errorf("wrong pkcs7 padding size")
	}
	return origData[:(dataLen - padLen)], nil
}

// AES-CBC
func encryptBytes(key []byte, out, in []byte, plainLen int) ([]byte, error) {
	if len(key) == 0 {
		return in[:plainLen], nil
	}
	total := pkcs7Padding(in, plainLen, 16) + plainLen
	C.aes_cbc_encrypt_c((*C.uint8_t)(unsafe.Pointer(&key[0])), (*C.uint8_t)(unsafe.Pointer(&cbcIVBlock[0])), (*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.uint8_t)(unsafe.Pointer(&in[0])), C.int(total))
	return out[:total], nil
}

func decryptBytes(key []byte, out, in []byte, dataLen int) ([]byte, error) {
	if len(key) == 0 {
		return in[:dataLen], nil
	}
	var outLen C.int
	C.aes_cbc_decrypt_c((*C.uint8_t)(unsafe.Pointer(&key[0])), (*C.uint8_t)(unsafe.Pointer(&cbcIVBlock[0])), (*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.uint8_t)(unsafe.Pointer(&in[0])), C.int(dataLen), &outLen)
	return out[:int(outLen)], nil
}

// {240e:3b7:622:3440:59ad:7fa1:170c:ef7f 47924975352157270363627191692449083263 China CN 0xc0000965c8 Guangdong GD 0  Guangzhou 23.1167 113.25 Asia/Shanghai AS4134 Chinanet }
func netInfo() *NetInfo {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 	var d net.Dialer
		// 	return d.DialContext(ctx, "tcp6", addr)
		// },
	}
	// sometime will be failed, retry
	for i := 0; i < 2; i++ {
		client := &http.Client{Transport: tr, Timeout: time.Second * 10}
		r, err := client.Get("https://ifconfig.co/json")
		if err != nil {
			gLog.d("netInfo error:%s", err)
			continue
		}
		defer r.Body.Close()
		buf := make([]byte, 1024*64)
		n, err := r.Body.Read(buf)
		if err != nil {
			gLog.d("netInfo error:%s", err)
			continue
		}
		rsp := NetInfo{}
		if err = json.Unmarshal(buf[:n], &rsp); err != nil {
			gLog.e("wrong NetInfo:%s", err)
			continue
		}
		return &rsp
	}
	return nil
}

func execOutput(name string, args ...string) string {
	cmdGetOsName := exec.Command(name, args...)
	var cmdOut bytes.Buffer
	cmdGetOsName.Stdout = &cmdOut
	cmdGetOsName.Run()
	return cmdOut.String()
}

func defaultNodeName() string {
	name, _ := os.Hostname()
	for len(name) < MinNodeNameLen {
		name = fmt.Sprintf("%s%d", name, rand.Int()%10)
	}
	return name
}

const EQUAL int = 0
const GREATER int = 1
const LESS int = -1

func compareVersion(v1, v2 string) int {
	cv1 := C.CString(v1)
	defer C.free(unsafe.Pointer(cv1))
	cv2 := C.CString(v2)
	defer C.free(unsafe.Pointer(cv2))
	return int(C.compare_version_c(cv1, cv2))
}

func parseMajorVer(ver string) int {
	cVer := C.CString(ver)
	defer C.free(unsafe.Pointer(cVer))
	return int(C.parse_major_ver_c(cVer))
}

func IsIPv6(ipStr string) bool {
	cStr := C.CString(ipStr)
	defer C.free(unsafe.Pointer(cStr))
	return C.is_ipv6_c(cStr) != 0
}

func IsLocalhost(ipStr string) bool {
	cStr := C.CString(ipStr)
	defer C.free(unsafe.Pointer(cStr))
	return C.is_localhost_c(cStr) != 0
}

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-")

func randStr(n int) string {
	buf := make([]byte, n+1)
	C.rand_str_c((*C.char)(unsafe.Pointer(&buf[0])), C.int(n))
	return string(buf[:n])
}

func execCommand(commandPath string, wait bool, arg ...string) (err error) {
	command := exec.Command(commandPath, arg...)
	err = command.Start()
	if err != nil {
		return
	}
	if wait {
		err = command.Wait()
	}
	return
}

func sanitizeFileName(fileName string) string {
	cIn := C.CString(fileName)
	defer C.free(unsafe.Pointer(cIn))
	buf := make([]byte, len(fileName)+1)
	C.sanitize_file_name_c((*C.char)(unsafe.Pointer(&buf[0])), cIn)
	return string(buf[:len(fileName)])
}

func prettyJson(s interface{}) string {
	jsonData, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return ""
	}
	return string(jsonData)
}

func inetAtoN(ipstr string) (uint32, error) { // support both ipnet or single ip
	// Handle CIDR if present
	if strings.Contains(ipstr, "/") {
		i, _, err := net.ParseCIDR(ipstr)
		if err != nil {
			return 0, err
		}
		ipstr = i.String()
	}
	cStr := C.CString(ipstr)
	defer C.free(unsafe.Pointer(cStr))
	return uint32(C.inet_aton_c(cStr)), nil
}

func calculateChecksum(data []byte) uint16 {
	return uint16(C.calculate_checksum_c((*C.uint8_t)(unsafe.Pointer(&data[0])), C.int(len(data))))
}

func min(nums ...int32) int32 {
	if len(nums) == 0 {
		return 0
	}
	return int32(C.min_c((*C.int32_t)(unsafe.Pointer(&nums[0])), C.int(len(nums))))
}

func calcRetryTimeRelay(x float64) float64 {
	return float64(C.calc_retry_time_relay_c(C.double(x)))
}
func calcRetryTimeDirect(x float64) float64 {
	return float64(C.calc_retry_time_direct_c(C.double(x)))
}

func calcRTT(preRtt, currentRtt int32) int32 {
	return int32(C.calc_rtt_c(C.int32_t(preRtt), C.int32_t(currentRtt)))
}

func movingAverage(preVal, currentVal int64, factor float64) int64 {
	return int64(C.moving_average_c(C.int64_t(preVal), C.int64_t(currentVal), C.double(factor)))
}

func isAndroid() bool {
	if runtime.GOOS == "android" {
		return true
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "Android")
}

func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	// windows could not rename running executable, so copy then delete
	if runtime.GOOS == "windows" {
		err = copyFile(src, dst)
		if err != nil {
			return err
		}

		os.Remove(src)
	}
	return nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}

func resolveServerIP(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 先系统 DNS
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err == nil && len(ips) > 0 {
		gLog.i("system dns resolved %s -> %v", host, ips)
		return ips, nil
	}

	gLog.e("system dns resolve failed for %s: %v", host, err)
	gLog.i("retry with fallback dns...")

	// 再 fallback dns
	return lookupWithCustomDNS(ctx, host)
}
func lookupWithCustomDNS(ctx context.Context, domain string) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 5 * time.Second}

			// 先 119.29.29.29
			conn, err := dialer.DialContext(ctx, network, "119.29.29.29:53")
			if err == nil {
				return conn, nil
			}

			// 再 8.8.8.8
			return dialer.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	return resolver.LookupHost(ctx, domain)
}
