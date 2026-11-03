package ike

import (
	"bytes"
	"testing"
)

// buildChallengeRequest builds an EAP-AKA Challenge request whose
// server MAC is computed with the given KAut, so a client with a
// MockSIM returning the matching CK/IK will verify it.
func buildChallengeRequest(t *testing.T, id int, kaut []byte, randVal, autnVal []byte) []byte {
	t.Helper()
	randAttr, _ := MarshalAKAAttribute(AKAAttrRAND, append([]byte{0, 0}, randVal...))
	autnAttr, _ := MarshalAKAAttribute(AKAAttrAUTN, append([]byte{0, 0}, autnVal...))
	// MAC attribute value: 2 reserved + 16 MAC placeholder.
	macAttr, _ := MarshalAKAAttribute(AKAAttrMAC, make([]byte, 18))
	data := append([]byte{AKASubtypeChallenge, 0, 0}, randAttr...)
	data = append(data, autnAttr...)
	data = append(data, macAttr...)
	pkt, err := MarshalEAP(EAPPacket{Code: EAPRequest, Identifier: id, Type: EAPTypeAKA, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	// Patch MAC: find MAC attribute offset in the request.
	attrs, err := ParseAKAAttributes(data[3:])
	if err != nil {
		t.Fatal(err)
	}
	mac, err := oneAKAAttribute(attrs, AKAAttrMAC)
	if err != nil {
		t.Fatal(err)
	}
	// Zero the MAC field, compute, then patch.
	zeroed := append([]byte(nil), pkt...)
	off := 5 + 3 + mac.Offset
	for i := off + 4; i < off+20; i++ {
		zeroed[i] = 0
	}
	computed := AKAMAC(kaut, zeroed)
	copy(pkt[off+4:off+20], computed)
	return pkt
}

func TestEAPIdentityAndAKAIdentity(t *testing.T) {
	c, err := NewEAPAKAClient("0test@nai.epc.mnc033.mcc234.3gppnetwork.org", &MockSIM{RES: []byte{1, 2, 3, 4}, CK: bytes.Repeat([]byte{0x11}, 16), IK: bytes.Repeat([]byte{0x22}, 16)})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := MarshalEAP(EAPPacket{Code: EAPRequest, Identifier: 5, Type: EAPTypeIdentity})
	resp, ok, err := c.Handle(req)
	if err != nil || ok {
		t.Fatalf("identity: resp ok=%v err=%v", ok, err)
	}
	p, err := ParseEAP(resp)
	if err != nil || p.Code != EAPResponse || p.Type != EAPTypeIdentity || string(p.Data) != c.NAI {
		t.Fatalf("identity response = %+v err=%v", p, err)
	}
	// AKA-Identity with exactly one permanent-ID request.
	perm, _ := MarshalAKAAttribute(AKAAttrPermanentIDReq, []byte{0, 0})
	data := append([]byte{AKASubtypeIdentity, 0, 0}, perm...)
	req2, _ := MarshalEAP(EAPPacket{Code: EAPRequest, Identifier: 6, Type: EAPTypeAKA, Data: data})
	resp2, _, err := c.Handle(req2)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := ParseEAP(resp2)
	attrs, _ := ParseAKAAttributes(p2.Data[3:])
	idAttr, err := oneAKAAttribute(attrs, AKAAttrIdentity)
	if err != nil || !bytes.Contains(idAttr.Raw, []byte(c.NAI)) {
		t.Fatalf("AKA identity response bad: %v %v", idAttr, err)
	}
}

func TestEAPAKAChallengeWithMockSIM(t *testing.T) {
	nai := "0test@nai.epc.mnc033.mcc234.3gppnetwork.org"
	ck := bytes.Repeat([]byte{0x11}, 16)
	ik := bytes.Repeat([]byte{0x22}, 16)
	keys, err := DeriveAKAKeys([]byte(nai), ik, ck)
	if err != nil {
		t.Fatal(err)
	}
	sim := &MockSIM{RES: []byte{0xde, 0xad, 0xbe, 0xef}, CK: ck, IK: ik}
	c, _ := NewEAPAKAClient(nai, sim)
	randVal := bytes.Repeat([]byte{0x33}, 16)
	autnVal := bytes.Repeat([]byte{0x44}, 16)
	req := buildChallengeRequest(t, 9, keys.KAut, randVal, autnVal)
	resp, ok, err := c.Handle(req)
	if err != nil || ok {
		t.Fatalf("challenge: ok=%v err=%v", ok, err)
	}
	if sim.CallCount != 1 || !bytes.Equal(sim.LastRAND, randVal) || !bytes.Equal(sim.LastAUTN, autnVal) {
		t.Fatalf("SIM not called with RAND/AUTN: %+v", sim)
	}
	if !c.ChallengeComplete || len(c.Keys.MSK) != 64 || len(c.Keys.EMSK) != 64 {
		t.Fatalf("challenge not complete / keys wrong: %+v", c.Keys)
	}
	p, _ := ParseEAP(resp)
	attrs, _ := ParseAKAAttributes(p.Data[3:])
	resAttr, err := oneAKAAttribute(attrs, AKAAttrRES)
	if err != nil || !bytes.Contains(resAttr.Raw, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("RES attribute bad: %v %v", resAttr, err)
	}
	// Verify the response MAC verifies with KAut.
	macAttr, _ := oneAKAAttribute(attrs, AKAAttrMAC)
	zeroed := append([]byte(nil), resp...)
	off := 5 + 3 + macAttr.Offset
	for i := off + 4; i < off+20; i++ {
		zeroed[i] = 0
	}
	if !bytes.Equal(AKAMAC(keys.KAut, zeroed), macAttr.Raw[4:20]) {
		t.Fatal("response MAC does not verify")
	}
	// EAP-Success after a completed challenge succeeds.
	succ, _ := MarshalEAP(EAPPacket{Code: EAPSuccess, Identifier: 10})
	_, ok, err = c.Handle(succ)
	if err != nil || !ok {
		t.Fatalf("success after challenge: ok=%v err=%v", ok, err)
	}
}

func TestEAPAKAChallengeBadServerMAC(t *testing.T) {
	nai := "0test@nai.epc.mnc033.mcc234.3gppnetwork.org"
	sim := &MockSIM{RES: []byte{1, 2, 3, 4}, CK: bytes.Repeat([]byte{0x11}, 16), IK: bytes.Repeat([]byte{0x22}, 16)}
	c, _ := NewEAPAKAClient(nai, sim)
	// Build a request whose MAC was computed with a different key.
	wrongKeys, _ := DeriveAKAKeys([]byte(nai), bytes.Repeat([]byte{0x99}, 16), bytes.Repeat([]byte{0x88}, 16))
	req := buildChallengeRequest(t, 9, wrongKeys.KAut, bytes.Repeat([]byte{0x33}, 16), bytes.Repeat([]byte{0x44}, 16))
	if _, _, err := c.Handle(req); err == nil || err.Error() != "ike: EAP-AKA server MAC is invalid" {
		t.Fatalf("bad server MAC not rejected: %v", err)
	}
	if c.ChallengeComplete {
		t.Fatal("challenge marked complete after bad MAC")
	}
}

func TestEAPAKASyncFailure(t *testing.T) {
	nai := "0test@nai.epc.mnc033.mcc234.3gppnetwork.org"
	auts := bytes.Repeat([]byte{0x55}, 14)
	sim := &MockSIM{SyncAUTS: auts}
	c, _ := NewEAPAKAClient(nai, sim)
	// Server MAC is irrelevant on the sync path: SIM returns
	// AUTS before MAC verification in our implementation, matching
	// VoCat's order (provider first, then MAC check only on RES).
	// Build a request with any MAC; the client should still
	// return SyncFailure, because Authenticate is called first.
	keys, _ := DeriveAKAKeys([]byte(nai), bytes.Repeat([]byte{0x22}, 16), bytes.Repeat([]byte{0x11}, 16))
	req := buildChallengeRequest(t, 9, keys.KAut, bytes.Repeat([]byte{0x33}, 16), bytes.Repeat([]byte{0x44}, 16))
	resp, _, err := c.Handle(req)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ParseEAP(resp)
	if p.Data[0] != AKASubtypeSyncFailure {
		t.Fatalf("sync failure subtype = %d", p.Data[0])
	}
	attrs, _ := ParseAKAAttributes(p.Data[3:])
	autsAttr, err := oneAKAAttribute(attrs, AKAAttrAUTS)
	if err != nil || !bytes.Contains(autsAttr.Raw, auts) {
		t.Fatalf("AUTS attribute bad: %v %v", autsAttr, err)
	}
}

func TestEAPFailureAndSuccessBeforeChallenge(t *testing.T) {
	c, _ := NewEAPAKAClient("0test@nai", &MockSIM{})
	fail, _ := MarshalEAP(EAPPacket{Code: EAPFailure, Identifier: 1})
	if _, _, err := c.Handle(fail); err == nil {
		t.Fatal("EAP failure not rejected")
	}
	succ, _ := MarshalEAP(EAPPacket{Code: EAPSuccess, Identifier: 1})
	if _, _, err := c.Handle(succ); err == nil {
		t.Fatal("success before challenge not rejected")
	}
}

func TestDeriveAKAKeysLengths(t *testing.T) {
	keys, err := DeriveAKAKeys([]byte("identity"), bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16))
	if err != nil || len(keys.KEncr) != 16 || len(keys.KAut) != 16 || len(keys.MSK) != 64 || len(keys.EMSK) != 64 {
		t.Fatalf("key lengths wrong: %+v %v", keys, err)
	}
	if _, err := DeriveAKAKeys([]byte("identity"), []byte{1}, bytes.Repeat([]byte{2}, 16)); err == nil {
		t.Fatal("short IK accepted")
	}
}
