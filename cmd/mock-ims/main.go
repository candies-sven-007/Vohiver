// Command mock-ims runs the IMS REGISTER skeleton end to end
// WITHOUT any socket.
//
// This container blocks UDP even on loopback, and this demo
// deliberately also uses no TCP: the client calls MockServer.Handle
// directly in memory. It prints the two-step exchange:
//
//	REGISTER (no Authorization) -> 401 WWW-Authenticate AKA
//	REGISTER (Digest AKAv1-MD5 Authorization) -> 200 OK
//
// A real P-CSCF transport (UDP/TCP over the IKE tunnel) and a real
// USIM AUTHENTICATE (replacing MockSIM) are later steps, not done
// here. No host is contacted and nothing is sent on a network.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/candies-sven-007/vohiver/internal/ims"
)

func main() {
	// Synthetic identity only: MCC 234, MNC candidate 33.
	id, err := ims.DeriveIdentity("234330123456789", "234", "33", "")
	if err != nil {
		fatal(err)
	}
	randBytes := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	autn := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	res := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	ck := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}
	ik := []byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f}

	mock := ims.NewMockServer(id.IMSDomain, randBytes, autn, res, id.IMPI, id.IMSDomain)
	client := &ims.Client{
		Identity: id,
		SIM:      &ims.MockSIM{RES: res, CK: ck, IK: ik},
		CallID:   "mock-ims-call-1", FromTag: "mock-tag-1", Branch: "mock-br-1",
		CNonce: "mock-cnonce", CSeq: 1, Expires: 3600, ViaHost: "192.0.2.1:5060",
	}
	result, err := client.Register(mock.Handle)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("IMPI: %s\nSIP IMPU: %s\nTel IMPU: %s\n", id.IMPI, id.SIPIMPU, id.TelIMPU)
	fmt.Printf("first REGISTER has Authorization: %v\n", strings.Contains(result.FirstRequest, "Authorization:"))
	fmt.Printf("challenge RAND=%x AUTN=%x\n", result.Challenge.RAND, result.Challenge.AUTN)
	fmt.Printf("second REGISTER has Authorization: %v\n", strings.Contains(result.SecondRequest, "Authorization: Digest "))
	fmt.Printf("AKA RES=%x CK len=%d IK len=%d\n", result.AKA.RES, len(result.AKA.CK), len(result.AKA.IK))
	fmt.Printf("mock saw %d requests, final status: %d OK (in-memory, no socket)\n", len(mock.Seen), result.StatusCode)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
