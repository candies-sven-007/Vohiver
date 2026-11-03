package ike

import (
	"encoding/binary"
	"math/big"
	"testing"
)

// These tests never touch UDP, so they run in this container.
// UDP is tested separately, once, on a host where UDP is allowed
// (UK VPS or the stick), via cmd/ike-probe + cmd/mock-epdg.
func TestBuildSAInitStructure(t *testing.T) {
	pkt := BuildSAInit()
	if len(pkt) != 248 {
		t.Fatalf("SA_INIT len = %d, want 248", len(pkt))
	}
	if binary.BigEndian.Uint32(pkt[24:28]) != uint32(len(pkt)) {
		t.Fatalf("header length field wrong")
	}
	if pkt[16] != 33 || pkt[17] != 0x20 || pkt[18] != 34 || pkt[19] != 0x08 {
		t.Fatalf("header next/version/exchange/flags = %d/%x/%d/%x, want 33/20/34/08 (initiator bit)", pkt[16], pkt[17], pkt[18], pkt[19])
	}
	// Proposal at 28+4=32: last, reserved, length, then number, protocol IKE=1, SPI size, transforms.
	if pkt[36] != 1 || pkt[37] != 1 {
		t.Fatalf("proposal number/protocol = %d/%d, want 1/1", pkt[36], pkt[37])
	}
	// SA payload at 28: next=KE(34), len=48.
	if pkt[28] != 34 || binary.BigEndian.Uint16(pkt[30:32]) != 48 {
		t.Fatalf("SA payload next/len = %d/%d, want 34/48", pkt[28], binary.BigEndian.Uint16(pkt[30:32]))
	}
	// KE payload at 28+48=76: next=Ni(40), DH group 2, len=136.
	if pkt[76] != 40 || binary.BigEndian.Uint16(pkt[78:80]) != 136 || binary.BigEndian.Uint16(pkt[80:82]) != 2 {
		t.Fatalf("KE payload wrong: next=%d len=%d group=%d", pkt[76], binary.BigEndian.Uint16(pkt[78:80]), binary.BigEndian.Uint16(pkt[80:82]))
	}
	// Ni payload at 76+136=212: next=0, len=36.
	if pkt[212] != 0 || binary.BigEndian.Uint16(pkt[214:216]) != 36 {
		t.Fatalf("Ni payload wrong: next=%d len=%d", pkt[212], binary.BigEndian.Uint16(pkt[214:216]))
	}
}

func TestDHPublicIsValidMODP1024(t *testing.T) {
	p, _ := new(big.Int).SetString(modp1024Prime, 16)
	q := new(big.Int).Sub(p, big.NewInt(1))
	q.Div(q, big.NewInt(2))
	for i := 0; i < 5; i++ {
		pubBytes := dhPublic()
		if len(pubBytes) != 128 {
			t.Fatalf("DH public len = %d, want 128", len(pubBytes))
		}
		pub := new(big.Int).SetBytes(pubBytes)
		if pub.Cmp(big.NewInt(1)) <= 0 || pub.Cmp(p) >= 0 {
			t.Fatalf("DH public out of range")
		}
		// Valid MODP1024 public values are quadratic residues: pub^q mod p == 1.
		if new(big.Int).Exp(pub, q, p).Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("DH public is not a quadratic residue mod p")
		}
	}
}
