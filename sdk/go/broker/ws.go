// Minimal WebSocket client (stdlib only) for broker /ws subscriptions.
package broker

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WSClient is a minimal WebSocket client.
type WSClient struct {
	conn   net.Conn
	tls    *tls.Conn
	mu     sync.Mutex
	closed bool
}

// WSMessage represents a text frame from the broker.
type WSMessage struct {
	Type      string          `json:"type"`
	EventType string          `json:"event_type"`
	Data      json.RawMessage `json:"data"`
	TS        string          `json:"ts"`
	Code      string          `json:"code,omitempty"`
	Message   string          `json:"message,omitempty"`
}

// WSAckType is the ack_type field on type=ack messages.
type WSAckType string

const (
	WSAckConnected    WSAckType = "connected"
	WSAckSubscribed   WSAckType = "subscribed"
	WSAckUnsubscribed WSAckType = "unsubscribed"
	WSAckPong         WSAckType = "pong"
)

// WSConnect opens a WebSocket connection to wss://host:port/path.
func WSConnect(endpoint, path string, tlsCfg *tls.Config) (*WSClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tlsCfg.ServerName = host
	addr := net.JoinHostPort(host, port)
	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	c := &WSClient{conn: tlsConn, tls: tlsConn}
	// Send HTTP Upgrade
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		c.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	pathClean := strings.TrimPrefix(path, "/")
	req := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: secret-broker-go/%s\r\n\r\n",
		pathClean, host, key, Version)
	if err := tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	// Read response
	buf := make([]byte, 1024)
	if err := tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.Close()
		return nil, err
	}
	n, err := tlsConn.Read(buf)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "101") {
		c.Close()
		return nil, fmt.Errorf("upgrade failed: %s", firstLine(resp))
	}
	// Validate Sec-WebSocket-Accept (optional)
	hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	expected := base64.StdEncoding.EncodeToString(hash[:])
	if !strings.Contains(resp, expected) {
		// Some brokers skip; we don't hard-fail
	}
	return c, nil
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// Subscribe sends a subscribe frame.
func (c *WSClient) Subscribe(events []string, filter map[string]any) error {
	msg := map[string]any{
		"action": "subscribe",
		"events": events,
	}
	if filter != nil {
		msg["filter"] = filter
	}
	return c.sendJSON(msg)
}

// Unsubscribe sends an unsubscribe frame.
func (c *WSClient) Unsubscribe(events []string) error {
	return c.sendJSON(map[string]any{"action": "unsubscribe", "events": events})
}

// Ping sends a ping frame.
func (c *WSClient) Ping() error {
	return c.sendJSON(map[string]any{"action": "ping"})
}

// Recv reads the next JSON message.
func (c *WSClient) Recv() (*WSMessage, error) {
	for {
		op, data, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		if op == 0x8 {
			return nil, fmt.Errorf("ws closed")
		}
		if op == 0x9 {
			// ping → pong
			if err := c.writeFrame(0xA, data); err != nil {
				return nil, err
			}
			continue
		}
		if op == 0xA {
			continue
		}
		var m WSMessage
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("decode message: %w", err)
		}
		return &m, nil
	}
}

// Close closes the connection.
func (c *WSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.tls != nil {
		// Best-effort close frame
		_ = c.writeFrame(0x8, []byte{})
		_ = c.tls.Close()
	}
	return nil
}

// ============================================================
// Frame I/O
// ============================================================

func (c *WSClient) sendJSON(obj any) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return c.writeFrame(0x1, b)
}

func (c *WSClient) writeFrame(opcode byte, data []byte) error {
	if c.tls == nil {
		return fmt.Errorf("not connected")
	}
	if err := c.tls.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	header := []byte{0x80 | opcode}
	ln := len(data)
	switch {
	case ln < 126:
		header = append(header, byte(ln))
	case ln < 65536:
		header = append(header, 126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(ln))
	default:
		header = append(header, 127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(ln))
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	header = append(header, mask...)
	masked := make([]byte, ln)
	for i, b := range data {
		masked[i] = b ^ mask[i%4]
	}
	if _, err := c.tls.Write(header); err != nil {
		return err
	}
	if _, err := c.tls.Write(masked); err != nil {
		return err
	}
	return nil
}

func (c *WSClient) readFrame() (byte, []byte, error) {
	if c.tls == nil {
		return 0, nil, fmt.Errorf("not connected")
	}
	if err := c.tls.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return 0, nil, err
	}
	hdr := make([]byte, 2)
	if _, err := readFull(c.tls, hdr); err != nil {
		return 0, nil, err
	}
	fin := hdr[0] & 0x80
	_ = fin
	op := hdr[0] & 0x0F
	masked := hdr[1] & 0x80
	ln := int(hdr[1] & 0x7F)
	if ln == 126 {
		buf := make([]byte, 2)
		if _, err := readFull(c.tls, buf); err != nil {
			return 0, nil, err
		}
		ln = int(binary.BigEndian.Uint16(buf))
	} else if ln == 127 {
		buf := make([]byte, 8)
		if _, err := readFull(c.tls, buf); err != nil {
			return 0, nil, err
		}
		ln = int(binary.BigEndian.Uint64(buf))
	}
	var maskKey []byte
	if masked != 0 {
		maskKey = make([]byte, 4)
		if _, err := readFull(c.tls, maskKey); err != nil {
			return 0, nil, err
		}
	}
	data := make([]byte, ln)
	if _, err := readFull(c.tls, data); err != nil {
		return 0, nil, err
	}
	if maskKey != nil {
		for i := range data {
			data[i] ^= maskKey[i%4]
		}
	}
	return op, data, nil
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
