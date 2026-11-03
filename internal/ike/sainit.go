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
const modp1024Prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"

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

// PinnedSA is the single proven SA proposal. It must never grow
// into a multi-proposal packet: the gsm-sip-bridge research notes
// record an 852-byte default proposal set that an ePDG answered
// with a bare INVALID_SYNTAX on every attempt. This proposal is
// 48 bytes in the SA payload, and the whole SA_INIT is 248 bytes
// without a cookie.
func PinnedSA() (encrID, prfID, integID, dhID int, keyLen int) {
	return 12, 2, 2, 2, 128
}

// BuildSAInit returns one IKEv2 IKE_SA_INIT packet without a cookie.
func BuildSAInit() []byte {
	return BuildSAInitWithCookie(nil, nil)
}

// BuildSAInitWithCookie returns one IKE_SA_INIT packet. When cookie
// is non-empty, the COOKIE Notify (type 16390, VoCat's notifyCookie)
// is the FIRST payload, exactly as VoCat's provider does, and the
// SA payload follows it. When spi is non-nil it is reused (cookie
// retries must keep the same initiator SPI); otherwise a fresh
// random SPI is generated.
func BuildSAInitWithCookie(cookie, spi []byte) []byte {
	encrAttr := []byte{0x80, 0x0e, 0x00, 0x80}
	transforms := [][]byte{
		transform(3, 1, 12, encrAttr),
		transform(3, 2, 2, nil),
		transform(3, 3, 2, nil),
		transform(0, 4, 2, nil),
	}
	propBody := []byte{1, 1, 0, 4}
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
	if spi == nil {
		spi = make([]byte, 8)
		rand.Read(spi)
	}
	hdr := make([]byte, 28)
	copy(hdr[0:8], spi)
	hdr[17] = 0x20
	hdr[18] = 34
	hdr[19] = 0x08
	var payloads []byte
	if len(cookie) > 0 {
		// Notify payload: generic header (next=SA) + body
		// (protocol 0, SPI size 0, type 16390, cookie data).
		notifyBody := []byte{0, 0, 0, 0}
		binary.BigEndian.PutUint16(notifyBody[2:4], NotifyCookie)
		notifyBody = append(notifyBody, cookie...)
		notify := []byte{33, 0, 0, 0}
		notify = append(notify, notifyBody...)
		binary.BigEndian.PutUint16(notify[2:4], uint16(len(notify)))
		payloads = append(payloads, notify...)
		hdr[16] = PayloadNotify
	} else {
		hdr[16] = 33
	}
	payloads = append(payloads, sa...)
	payloads = append(payloads, ke...)
	payloads = append(payloads, ni...)
	total := 28 + len(payloads)
	binary.BigEndian.PutUint32(hdr[24:28], uint32(total))
	pkt := append(hdr, payloads...)
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
	CookieRounds int    `json:"cookie_rounds"`
	CookieSeen   bool   `json:"cookie_seen"`
}

// MaxCookieRounds bounds COOKIE challenges, matching VoCat's
// maxIKEInitCookieChallenges = 4. A fifth cookie is an error, not
// another retry: the ePDG is not going to accept the SA.
const MaxCookieRounds = 4

// ProbeSAInit sends SA_INIT via proxy (or directly when proxy is
// empty) and returns the response summary. It handles COOKIE
// challenges: if a response carries exactly one COOKIE notify and
// no SA, it resends the same initiator SPI with that cookie as
// the first payload, up to MaxCookieRounds rounds. Each round
// retries a timeout up to 3 times with a fresh DH/nonce but the
// same SPI and cookie. A single timeout is not proof the ePDG is
// dead, and a cookie is not a failure: it is the ePDG's
// anti-flood check (Cisco ePDG docs: at most 8 IKE_INITs per
// source IP/port before cookie/rate-limit behaviour).
func ProbeSAInit(proxyURL, targetIP string, targetPort int) ProbeResult {
	spi := make([]byte, 8)
	rand.Read(spi)
	var cookie []byte
	attempts := 0
	for round := 0; round < MaxCookieRounds; round++ {
		var lastErr string
		var resp []byte
		gotResp := false
		for try := 0; try < 3; try++ {
			attempts++
			var conn net.Conn
			var err error
			if proxyURL != "" {
				conn, err = egress.Dial(proxyURL, targetIP, targetPort, 5*time.Second)
			} else {
				conn, err = net.DialTimeout("udp", net.JoinHostPort(targetIP, fmt.Sprint(targetPort)), 5*time.Second)
			}
			if err != nil {
				return ProbeResult{OK: false, Error: "dial: " + err.Error(), Attempts: attempts, CookieRounds: round, CookieSeen: len(cookie) > 0}
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(BuildSAInitWithCookie(cookie, spi)); err != nil {
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
			resp = append([]byte(nil), buf[:n]...)
			gotResp = true
			break
		}
		if !gotResp {
			return ProbeResult{OK: false, Error: lastErr, Attempts: attempts, CookieRounds: round, CookieSeen: len(cookie) > 0}
		}
		if len(resp) < 28 {
			return ProbeResult{OK: false, Error: fmt.Sprintf("short response: %d bytes", len(resp)), Attempts: attempts, CookieRounds: round, CookieSeen: len(cookie) > 0}
		}
		dec, err := Decode(resp)
		if err != nil {
			return ProbeResult{OK: false, Error: "decode: " + err.Error(), Attempts: attempts, CookieRounds: round, CookieSeen: len(cookie) > 0}
		}
		newCookie, hasCookie, err := ExtractCookie(dec)
		if err != nil {
			return ProbeResult{OK: false, Error: err.Error(), Attempts: attempts, CookieRounds: round, CookieSeen: len(cookie) > 0}
		}
		if hasCookie && !dec.HasSA() {
			cookie = newCookie
			continue
		}
		if dec.HasSA() {
			return ProbeResult{OK: true, ResponseLen: len(resp), Exchange: dec.Header.Exchange, ResponderSPI: dec.Header.ResponderSPI, Attempts: attempts, CookieRounds: round, CookieSeen: len(cookie) > 0}
		}
		return ProbeResult{OK: false, Error: "response has neither SA nor COOKIE", Attempts: attempts, CookieRounds: round, CookieSeen: len(cookie) > 0}
	}
	return ProbeResult{OK: false, Error: "too many COOKIE challenges", Attempts: attempts, CookieRounds: MaxCookieRounds, CookieSeen: true}
}
