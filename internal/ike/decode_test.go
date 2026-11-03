package ike

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestPinnedProposalNever852(t *testing.T) {
	pkt := BuildSAInit()
	if len(pkt) >= 852 {
		t.Fatalf("SA_INIT len = %d, must never reach the 852-byte default proposal size", len(pkt))
	}
	dec, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Payloads) != 3 {
		t.Fatalf("payloads = %d, want 3 (SA, KE, Ni)", len(dec.Payloads))
	}
	sa := dec.Payloads[0]
	if len(sa.Proposals) != 1 {
		t.Fatalf("proposals = %d, want exactly 1 pinned proposal", len(sa.Proposals))
	}
	pr := sa.Proposals[0]
	if len(pr.Transforms) != 4 {
		t.Fatalf("transforms = %d, want 4", len(pr.Transforms))
	}
	want := []Transform{
		{Type: 1, ID: 12, KeyLen: 128, HasKeyLen: true},
		{Type: 2, ID: 2, KeyLen: -1},
		{Type: 3, ID: 2, KeyLen: -1},
		{Type: 4, ID: 2, KeyLen: -1},
	}
	for i, w := range want {
		got := pr.Transforms[i]
		if got.Type != w.Type || got.ID != w.ID || got.KeyLen != w.KeyLen || got.HasKeyLen != w.HasKeyLen {
			t.Fatalf("transform %d = %+v, want %+v", i, got, w)
		}
	}
	encr, prf, integ, dh, keyLen := PinnedSA()
	if encr != 12 || prf != 2 || integ != 2 || dh != 2 || keyLen != 128 {
		t.Fatalf("PinnedSA = %d/%d/%d/%d/%d", encr, prf, integ, dh, keyLen)
	}
}

func TestDecodeRoundTripAndCookie(t *testing.T) {
	pkt := BuildSAInit()
	dec, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Header.Exchange != 34 || dec.Header.NextPayload != PayloadSA {
		t.Fatalf("header wrong: %+v", dec.Header)
	}
	if !dec.HasSA() {
		t.Fatal("decoded packet should have SA")
	}
	// Cookie packet: same SPI, cookie as first payload.
	spi := pkt[0:8]
	cookie := []byte("test-cookie-1234")
	withCookie := BuildSAInitWithCookie(cookie, spi)
	dec2, err := Decode(withCookie)
	if err != nil {
		t.Fatal(err)
	}
	if dec2.Header.NextPayload != PayloadNotify {
		t.Fatalf("cookie packet first payload = %d, want Notify", dec2.Header.NextPayload)
	}
	if dec2.Header.InitiatorSPI != dec.Header.InitiatorSPI {
		t.Fatalf("cookie retry must keep initiator SPI: %s vs %s", dec2.Header.InitiatorSPI, dec.Header.InitiatorSPI)
	}
	if len(dec2.Payloads) != 4 {
		t.Fatalf("cookie packet payloads = %d, want 4 (Notify, SA, KE, Ni)", len(dec2.Payloads))
	}
	if dec2.Payloads[0].NotifyType != NotifyCookie {
		t.Fatalf("notify type = %d, want %d (COOKIE)", dec2.Payloads[0].NotifyType, NotifyCookie)
	}
	// A synthetic COOKIE-only response must extract exactly.
	resp := make([]byte, 28)
	copy(resp[0:8], spi)
	resp[16] = PayloadNotify
	resp[17] = 0x20
	resp[18] = 34
	resp[19] = 0x20
	notifyBody := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint16(notifyBody[2:4], NotifyCookie)
	notifyBody = append(notifyBody, cookie...)
	notify := []byte{0, 0, 0, 0}
	notify = append(notify, notifyBody...)
	binary.BigEndian.PutUint16(notify[2:4], uint16(len(notify)))
	resp = append(resp, notify...)
	binary.BigEndian.PutUint32(resp[24:28], uint32(len(resp)))
	dec3, err := Decode(resp)
	if err != nil {
		t.Fatal(err)
	}
	if dec3.HasSA() {
		t.Fatal("cookie-only response must not have SA")
	}
	got, has, err := ExtractCookie(dec3)
	if err != nil || !has || string(got) != string(cookie) {
		t.Fatalf("ExtractCookie = %q %v %v, want %q", got, has, err, cookie)
	}
}

func TestDecodeRejectsTruncatedAndBadLength(t *testing.T) {
	if _, err := Decode([]byte{1, 2, 3}); err == nil {
		t.Fatal("short packet must be rejected")
	}
	pkt := BuildSAInit()
	bad := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint32(bad[24:28], 9999)
	if _, err := Decode(bad); err == nil {
		t.Fatal("length mismatch must be rejected")
	}
	dec, err := Decode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dec.String(), "transform type=1 id=12 keylen=128") {
		t.Fatalf("decoded output missing pinned transform:\n%s", dec.String())
	}
}
