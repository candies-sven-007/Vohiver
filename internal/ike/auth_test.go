package ike

import (
	"strings"
	"testing"
)

func TestPermanentNAI(t *testing.T) {
	nai, err := PermanentNAI("123456789012345", "234", "33")
	if err != nil {
		t.Fatal(err)
	}
	if nai != "0123456789012345@nai.epc.mnc033.mcc234.3gppnetwork.org" {
		t.Fatalf("NAI = %q", nai)
	}
	if _, err := PermanentNAI("12345a", "234", "33"); err == nil {
		t.Fatal("non-digit IMSI accepted")
	}
	if _, err := PermanentNAI("12345", "23", "33"); err == nil {
		t.Fatal("short MCC accepted")
	}
}

func TestBuildAuth1ChainOrder(t *testing.T) {
	nai, _ := PermanentNAI("123456789012345", "234", "33")
	chain := BuildAuth1(nai, "ims")
	types, err := ParseAuthChainWithFirst(PayloadIDi, chain)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{PayloadIDi, PayloadIDr, PayloadNotify, PayloadNotify, PayloadNotify, PayloadSA, PayloadTSi, PayloadTSr, PayloadCP}
	if len(types) != len(want) {
		t.Fatalf("chain types = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("chain[%d] = %d, want %d (full %v)", i, types[i], want[i], types)
		}
	}
	// IDi body must carry the NAI, IDr body the APN.
	if !strings.Contains(string(chain), nai) || !strings.Contains(string(chain), "ims") {
		t.Fatal("AUTH(1) chain does not carry NAI/APN")
	}
}

func TestBuildAuthEAPAndFinal(t *testing.T) {
	eap := []byte{2, 7, 0, 4}
	chain := BuildAuthEAP(eap, nil)
	types, err := ParseAuthChainWithFirst(PayloadEAP, chain)
	if err != nil || len(types) != 1 || types[0] != PayloadEAP {
		t.Fatalf("EAP-only chain = %v, err %v", types, err)
	}
	chain2 := BuildAuthEAP(eap, []byte{0x01, 0x02})
	types2, err := ParseAuthChainWithFirst(PayloadEAP, chain2)
	if err != nil || len(types2) != 2 || types2[1] != PayloadNotify {
		t.Fatalf("EAP+DEVICE_IDENTITY chain = %v, err %v", types2, err)
	}
	fin := BuildAuthFinal(2, make([]byte, 16))
	types3, err := ParseAuthChainWithFirst(PayloadAuth, fin)
	if err != nil || len(types3) != 1 {
		t.Fatalf("AUTH final chain = %v, err %v", types3, err)
	}
}

func TestAuthFailureBeforeEAP(t *testing.T) {
	if !AuthFailureBeforeEAP([]uint16{NotifyAuthFailed}, false) {
		t.Fatal("AUTHENTICATION_FAILED before EAP not detected")
	}
	if AuthFailureBeforeEAP([]uint16{NotifyAuthFailed}, true) {
		t.Fatal("AUTHENTICATION_FAILED after EAP misclassified")
	}
	if AuthFailureBeforeEAP([]uint16{NotifyCookie}, false) {
		t.Fatal("COOKIE misclassified as auth failure")
	}
}

func TestParseAuthChainRejectsTruncation(t *testing.T) {
	chain := BuildAuth1("0x@nai", "ims")
	if _, err := ParseAuthChainWithFirst(PayloadIDi, chain[:len(chain)-3]); err == nil {
		t.Fatal("truncated AUTH chain accepted")
	}
}
