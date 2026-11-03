// Package ike builds IKEv2 packets. Only SA_INIT probing is here
// so far; EAP-AKA and IMS registration are the next steps.
package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/candies-sven-007/vohiver/internal/egress"
)

func transform(last byte, typ, id uint16, attr []byte) []byte {
	b := []byte{last, 0, 0, 0, byte(typ), 0, byte(id >> 8), byte(id)}
	b = append(b, attr...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

// BuildSAInit returns one IKEv2 IKE_SA_INIT packet. SA encoding
// follows MDD's swu_ike.py: ENCR AES_CBC id 12 key length 128,
// PRF HMAC_SHA1 id 2, INTEG HMAC_SHA1_96 id 2, DH MODP1024 id 2.
func BuildSAInit() []byte {
	encrAttr := []byte{0x80, 0x0e, 0x00, 0x80}
	transforms := [][]byte{
		transform(3, 1, 12, encrAttr),
		transform(3, 2, 2, nil),
		transform(3, 3, 2, nil),
		transform(0, 4, 2, nil),
	}
	propBody := []byte{1, 0, 0, 4}
	for _, t := range transforms {
		propBody = append(propBody, t...)
	}
	proposal := []byte{0, 0, 0, 0}
	proposal = append(proposal, propBody...)
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	sa := []byte{34, 0, 0, 0}
	sa = append(sa, proposal...)
	binary.BigEndian.PutUint16(sa[2:4], uint16(len(sa)))
	keData := make([]byte, 128)
	rand.Read(keData)
	ke := []byte{40, 0, 0, 0, 0, 2, 0, 0}
	ke = append(ke, keData...)
	binary.BigEndian.PutUint16(ke[2:4], uint16(len(ke)))
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ni := []byte{0, 0, 0, 0}
	ni = append(ni, nonce...)
	binary.BigEndian.PutUint16(ni[2:4], uint16(len(ni)))
	spi := make([]byte, 8)
	rand.Read(spi)
	hdr := make([]byte, 28)
	copy(hdr[0:8], spi)
	hdr[16] = 33
	hdr[17] = 0x20
	hdr[18] = 34
	hdr[19] = 0
	total := 28 + len(sa) + len(ke) + len(ni)
	binary.BigEndian.PutUint32(hdr[24:28], uint32(total))
	pkt := append(hdr, sa...)
	pkt = append(pkt, ke...)
	pkt = append(pkt, ni...)
	return pkt
}

// ProbeResult is the parsed SA_INIT response summary.
type ProbeResult struct {
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	ResponseLen  int    `json:"response_len"`
	Exchange     int    `json:"exchange"`
	ResponderSPI string `json:"responder_spi,omitempty"`
}

// ProbeSAInit sends one SA_INIT via proxy (or directly when proxy
// is empty) and returns the response summary.
func ProbeSAInit(proxyURL, targetIP string, targetPort int) ProbeResult {
	var conn net.Conn
	var err error
	if proxyURL != "" {
		conn, err = egress.Dial(proxyURL, targetIP, targetPort, 5*time.Second)
	} else {
		conn, err = net.DialTimeout("udp", net.JoinHostPort(targetIP, fmt.Sprint(targetPort)), 5*time.Second)
	}
	if err != nil {
		return ProbeResult{OK: false, Error: "dial: " + err.Error()}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(BuildSAInit()); err != nil {
		return ProbeResult{OK: false, Error: "write: " + err.Error()}
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return ProbeResult{OK: false, Error: "no response: " + err.Error()}
	}
	if n < 28 {
		return ProbeResult{OK: false, Error: fmt.Sprintf("short response: %d bytes", n)}
	}
	return ProbeResult{OK: true, ResponseLen: n, Exchange: int(buf[18]), ResponderSPI: fmt.Sprintf("%x", buf[8:16])}
}
