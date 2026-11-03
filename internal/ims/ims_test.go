package ims

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// These tests never touch UDP, TCP, or any socket, so they run in
// this container. The exchange is pure in-memory: Client.Register
// calls MockServer.Handle directly. A loopback UDP exchange is NOT
// claimed here (container UDP is blocked).

var (
	testIMSI = "234330123456789" // synthetic: MCC 234, MNC candidate 33
	testRAND = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	testAUTN = []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	testRES  = []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	testCK   = []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}
	testIK   = []byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f}
)

func testIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := DeriveIdentity(testIMSI, "234", "33", "")
	if err != nil {
		t.Fatalf("DeriveIdentity() error = %v", err)
	}
	return id
}

func testMock(id Identity) *MockServer {
	return NewMockServer("ims.mnc033.mcc234.3gppnetwork.org", testRAND, testAUTN, testRES, id.IMPI, id.IMSDomain)
}

func TestDeriveIdentityIMPIAndIMPU(t *testing.T) {
	id := testIdentity(t)
	if id.IMSDomain != "ims.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("IMSDomain = %q, want ims.mnc033.mcc234.3gppnetwork.org (MNC padded to 3 digits)", id.IMSDomain)
	}
	if id.IMPI != testIMSI+"@ims.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("IMPI = %q", id.IMPI)
	}
	if id.SIPIMPU != "sip:"+testIMSI+"@ims.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("SIPIMPU = %q", id.SIPIMPU)
	}
	if !strings.HasPrefix(id.TelIMPU, "tel:") {
		t.Fatalf("TelIMPU = %q, want tel: form", id.TelIMPU)
	}
}

func TestFirstRegisterHasNoAuthorization(t *testing.T) {
	id := testIdentity(t)
	req, err := BuildRegister(RegisterOptions{
		Identity: id, CallID: "call-1", FromTag: "tag-1", Branch: "br-1",
		CSeq: 1, Expires: 3600, ViaHost: "192.0.2.1:5060",
	})
	if err != nil {
		t.Fatalf("BuildRegister() error = %v", err)
	}
	if strings.Contains(req, "Authorization:") {
		t.Fatalf("first REGISTER must not carry Authorization:\n%s", req)
	}
	for _, want := range []string{
		"REGISTER sip:ims.mnc033.mcc234.3gppnetwork.org SIP/2.0",
		"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKbr-1;rport",
		"From: <sip:" + testIMSI + "@ims.mnc033.mcc234.3gppnetwork.org>;tag=tag-1",
		"To: <sip:" + testIMSI + "@ims.mnc033.mcc234.3gppnetwork.org>",
		"Call-ID: call-1",
		"CSeq: 1 REGISTER",
	} {
		if !strings.Contains(req, want) {
			t.Fatalf("first REGISTER missing %q:\n%s", want, req)
		}
	}
}

func TestParseChallengeExtractsNonceRANDAndAUTN(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(append(append([]byte(nil), testRAND...), testAUTN...))
	header := `Digest realm="ims.mnc033.mcc234.3gppnetwork.org", nonce="` + nonce + `", algorithm=AKAv1-MD5, qop="auth"`
	ch, err := ParseChallenge(header)
	if err != nil {
		t.Fatalf("ParseChallenge() error = %v", err)
	}
	if ch.Nonce != nonce {
		t.Fatalf("Nonce = %q, want %q", ch.Nonce, nonce)
	}
	if !bytes.Equal(ch.RAND, testRAND) {
		t.Fatalf("RAND = %x, want %x", ch.RAND, testRAND)
	}
	if !bytes.Equal(ch.AUTN, testAUTN) {
		t.Fatalf("AUTN = %x, want %x", ch.AUTN, testAUTN)
	}
	if ch.Algorithm != "AKAv1-MD5" || ch.QOP != "auth" {
		t.Fatalf("Algorithm/QOP = %q/%q, want AKAv1-MD5/auth", ch.Algorithm, ch.QOP)
	}
}

func TestParseChallengeRejectsNonAKAAndShortNonce(t *testing.T) {
	if _, err := ParseChallenge(`Digest realm="r", nonce="abc", algorithm=MD5, qop="auth"`); err == nil {
		t.Fatalf("non-AKA challenge must be rejected")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := ParseChallenge(`Digest realm="r", nonce="` + short + `", algorithm=AKAv1-MD5, qop="auth"`); err == nil {
		t.Fatalf("nonce shorter than RAND||AUTN (32 bytes) must be rejected")
	}
}

func TestMockServerFirstRegisterGets401(t *testing.T) {
	id := testIdentity(t)
	mock := testMock(id)
	req, _ := BuildRegister(RegisterOptions{Identity: id, CallID: "call-1", FromTag: "tag-1", Branch: "br-1", CSeq: 1})
	resp, err := ParseResponse(mock.Handle(req))
	if err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("first REGISTER status = %d, want 401", resp.StatusCode)
	}
	if resp.WWWAuthenticate == "" || !strings.Contains(resp.WWWAuthenticate, "AKAv1-MD5") {
		t.Fatalf("401 missing AKA WWW-Authenticate: %q", resp.WWWAuthenticate)
	}
}

func TestFullExchangeSecondRegisterCarriesAKAAuthorizationAndGets200(t *testing.T) {
	id := testIdentity(t)
	mock := testMock(id)
	client := &Client{
		Identity: id, SIM: &MockSIM{RES: testRES, CK: testCK, IK: testIK},
		CallID: "call-1", FromTag: "tag-1", Branch: "br-1",
		CNonce: "cnonce-fixed", CSeq: 1, Expires: 3600, ViaHost: "192.0.2.1:5060",
	}
	result, err := client.Register(mock.Handle)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result.StatusCode != 200 {
		t.Fatalf("final status = %d, want 200", result.StatusCode)
	}
	// First request: no Authorization; second: Authorization present.
	if strings.Contains(result.FirstRequest, "Authorization:") {
		t.Fatalf("first REGISTER in exchange carried Authorization")
	}
	if !strings.Contains(result.SecondRequest, "Authorization: Digest ") {
		t.Fatalf("second REGISTER missing Authorization:\n%s", result.SecondRequest)
	}
	if !strings.Contains(result.SecondRequest, "Call-ID: call-1") {
		t.Fatalf("second REGISTER changed Call-ID")
	}
	if !strings.Contains(result.SecondRequest, "CSeq: 2 REGISTER") {
		t.Fatalf("second REGISTER must increment CSeq to 2:\n%s", result.SecondRequest)
	}
	// Challenge material reached the SIM unchanged.
	if !bytes.Equal(result.Challenge.RAND, testRAND) || !bytes.Equal(result.Challenge.AUTN, testAUTN) {
		t.Fatalf("challenge RAND/AUTN = %x/%x, want %x/%x", result.Challenge.RAND, result.Challenge.AUTN, testRAND, testAUTN)
	}
	// MockSIM material is preserved (CK/IK are for the future IPsec
	// SA, not hashed into Digest, but must not be dropped).
	if !bytes.Equal(result.AKA.RES, testRES) || !bytes.Equal(result.AKA.CK, testCK) || !bytes.Equal(result.AKA.IK, testIK) {
		t.Fatalf("AKA RES/CK/IK not preserved: %x/%x/%x", result.AKA.RES, result.AKA.CK, result.AKA.IK)
	}
	// Response recomputed independently from MockSIM RES must match
	// the response carried in the second REGISTER.
	directives, err := parseDirectives(strings.TrimSpace(strings.TrimPrefix(result.Authorization, "Digest")))
	if err != nil {
		t.Fatalf("parse Authorization error = %v", err)
	}
	want := ComputeDigestResponse(id.IMPI, result.Challenge.Realm, testRES, "REGISTER", "sip:"+id.IMSDomain, result.Challenge.Nonce, "00000001", "cnonce-fixed", "auth")
	if directives["response"] != want {
		t.Fatalf("Authorization response = %q, want recomputed %q", directives["response"], want)
	}
	if directives["username"] != id.IMPI || directives["algorithm"] != "AKAv1-MD5" {
		t.Fatalf("Authorization username/algorithm = %q/%q", directives["username"], directives["algorithm"])
	}
	if len(mock.Seen) != 2 {
		t.Fatalf("mock saw %d requests, want 2", len(mock.Seen))
	}
}

func TestMockRejectsWrongRESWith403(t *testing.T) {
	id := testIdentity(t)
	mock := testMock(id)
	client := &Client{
		Identity: id, SIM: &MockSIM{RES: []byte{0x00, 0x00, 0x00, 0x00}, CK: testCK, IK: testIK},
		CallID: "call-1", FromTag: "tag-1", Branch: "br-1",
		CNonce: "cnonce-fixed", CSeq: 1, ViaHost: "192.0.2.1:5060",
	}
	_, err := client.Register(mock.Handle)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("wrong RES must fail with 403, got err = %v", err)
	}
}
