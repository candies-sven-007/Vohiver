// Package ike builds IKEv2 packets. Only SA_INIT probing is here
// so far; EAP-AKA and IMS registration are the next steps.
package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/candies-sven-007/vohiver/internal/egress"
)

// modp1024Prime is the RFC 2409 group 2 (MODP1024) prime.
const modp1024Prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

// dhPublic returns a real MODP1024 public value 2^priv mod p, padded
// to 128 bytes. A purely random 128-byte KE value is not a valid DH
// public value (about half of all random values are not quadratic
// residues mod p), and some responders silently drop such SA_INITs,
// which would look exactly like a timeout.
func dhPublic() []byte {
	p, _ := new(big.Int).SetString(modp1024Prime, 16)
	privBytes := make([]byte, 32)
	rand.Read(privBytes)
	priv := new(big.Int).SetBytes(privBytes)
	pub := new(big.Int).Exp(big.NewInt(2), priv, p)
	out := pub.Bytes()
	if len(out) < 128 {
		padded := make([]byte, 128)
		copy(padded[128-len(out):], out)
		return padded
	}
	return out
}

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
	keData := dhPublic()
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
	Attempts     int    `json:"attempts"`
}

// ProbeSAInit sends SA_INIT via proxy (or directly when proxy is
// empty), retrying up to 3 times with a fresh packet each time, and
// returns the response summary. A single timeout is not proof the
// ePDG is dead: a responder may drop one SA_INIT, so retries are
// part of the probe, not a new test.
func ProbeSAInit(proxyURL, targetIP string, targetPort int) ProbeResult {
	var lastErr string
	for attempt := 1; attempt <= 3; attempt++ {
		var conn net.Conn
		var err error
		if proxyURL != "" {
			conn, err = egress.Dial(proxyURL, targetIP, targetPort, 5*time.Second)
		} else {
			conn, err = net.DialTimeout("udp", net.JoinHostPort(targetIP, fmt.Sprint(targetPort)), 5*time.Second)
		}
		if err != nil {
			return ProbeResult{OK: false, Error: "dial: " + err.Error(), Attempts: attempt}
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(BuildSAInit()); err != nil {
			conn.Close()
			lastErr = "write: " + err.Error()
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = "no response: " + err.Error()
			continue
		}
		if n < 28 {
			return ProbeResult{OK: false, Error: fmt.Sprintf("short response: %d bytes", n), Attempts: attempt}
		}
		return ProbeResult{OK: true, ResponseLen: n, Exchange: int(buf[18]), ResponderSPI: fmt.Sprintf("%x", buf[8:16]), Attempts: attempt}
	}
	return ProbeResult{OK: false, Error: lastErr, Attempts: 3}
}
