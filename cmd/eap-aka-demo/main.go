// Command eap-aka-demo runs a complete EAP-AKA exchange against
// a mock SIM, in this container, with no UDP and no real card.
// It proves the frame handling end to end: NAI, Identity,
// AKA-Identity, Challenge (server MAC verified, RES + client
// MAC returned), then EAP-Success. The mock SIM's RES/CK/IK
// are fixed test values; the real SIM adapter plugs into the
// same SIMAKA interface in the full stack.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/candies-sven-007/vohiver/internal/ike"
)

func main() {
	nai, err := ike.PermanentNAI("123456789012345", "234", "33")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("NAI:", nai)
	fmt.Println("AUTH(1) chain types: IDi IDr EAP_ONLY MOBIKE INITIAL_CONTACT SA TSi TSr CP")
	chain := ike.BuildAuth1(nai, "ims")
	types, err := ike.ParseAuthChainWithFirst(ike.PayloadIDi, chain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("AUTH(1) parsed:", types)

	ck := bytes.Repeat([]byte{0x11}, 16)
	ik := bytes.Repeat([]byte{0x22}, 16)
	keys, _ := ike.DeriveAKAKeys([]byte(nai), ik, ck)
	sim := &ike.MockSIM{RES: []byte{0xde, 0xad, 0xbe, 0xef}, CK: ck, IK: ik}
	client, err := ike.NewEAPAKAClient(nai, sim)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Build a challenge request whose server MAC verifies.
	randVal := bytes.Repeat([]byte{0x33}, 16)
	autnVal := bytes.Repeat([]byte{0x44}, 16)
	randAttr, _ := ike.MarshalAKAAttribute(ike.AKAAttrRAND, append([]byte{0, 0}, randVal...))
	autnAttr, _ := ike.MarshalAKAAttribute(ike.AKAAttrAUTN, append([]byte{0, 0}, autnVal...))
	macAttr, _ := ike.MarshalAKAAttribute(ike.AKAAttrMAC, make([]byte, 18))
	data := append([]byte{ike.AKASubtypeChallenge, 0, 0}, randAttr...)
	data = append(data, autnAttr...)
	data = append(data, macAttr...)
	req, _ := ike.MarshalEAP(ike.EAPPacket{Code: ike.EAPRequest, Identifier: 9, Type: ike.EAPTypeAKA, Data: data})
	// Patch server MAC.
	attrs, _ := ike.ParseAKAAttributes(data[3:])
	// Find MAC offset by re-parsing: the MAC attribute is third.
	off := 5 + 3
	for _, a := range attrs {
		if a.Type == ike.AKAAttrMAC {
			break
		}
		off += len(a.Raw)
	}
	zeroed := append([]byte(nil), req...)
	for i := off + 4; i < off+20; i++ {
		zeroed[i] = 0
	}
	copy(req[off+4:off+20], ike.AKAMAC(keys.KAut, zeroed))

	resp, ok, err := client.Handle(req)
	if err != nil || ok {
		fmt.Fprintln(os.Stderr, "challenge failed:", err, ok)
		os.Exit(1)
	}
	fmt.Println("challenge response hex:", hex.EncodeToString(resp))
	fmt.Println("challenge complete:", client.ChallengeComplete, "SIM calls:", sim.CallCount)
	succ, _ := ike.MarshalEAP(ike.EAPPacket{Code: ike.EAPSuccess, Identifier: 10})
	_, ok, err = client.Handle(succ)
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "success failed:", err, ok)
		os.Exit(1)
	}
	fmt.Println("EAP-Success accepted: true")
}
