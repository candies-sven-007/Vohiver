// Package ike, auth.go: IKE_AUTH frame handling, state_2/3/4 in
// MDD swu_ike.py terms, reusing VoCat's ike/provider.go ordering
// and MDD's create_IKE_AUTH / IKE_AUTH_2 / IKE_AUTH_3 payloads.
//
// This file builds and parses the *unencrypted* payload chains
// that sit inside the SK (encrypted) payload. It does NOT do SK
// encryption, DH key derivation, or PRF-based AUTH verification:
// those need the negotiated IKE SA keys, which only exist after a
// real SA_INIT response. What it does prove, without UDP and
// without a real card, is the frame layout the ePDG expects:
//   state_2 (IKE_AUTH 1): IDi -> IDr -> EAP_ONLY -> MOBIKE ->
//     INITIAL_CONTACT -> child SA -> TSi -> TSr -> CP
//   state_3 (IKE_AUTH 2): EAP response, optionally followed by
//     DEVICE_IDENTITY notify when the ePDG asked for it
//   state_4 (IKE_AUTH 3): AUTH payload only
// A responder AUTHENTICATION_FAILED before any EAP challenge is
// an AAA/HSS rejection (MDD state_2 comment), not a SIM/PIN
// problem: the SIM was never queried in that case.
package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// IKE_AUTH payload types (RFC 7296, VoCat wire.go).
const (
	PayloadIDi   = 35
	PayloadIDr   = 36
	PayloadAuth  = 39
	PayloadTSi   = 44
	PayloadTSr   = 45
	PayloadSK    = 46
	PayloadCP    = 47
	PayloadEAP   = 48
	ExchangeAuth = 35
)

// IKE_AUTH notify types (VoCat wire.go, MDD swu_ike.py).
const (
	NotifyMOBIKESupported = 16396
	NotifyEAPOnlyAuth     = 16417
	NotifyDeviceIdentity  = 41101
	NotifyAuthFailed      = 24
)

// PermanentNAI builds the EAP-AKA permanent identity, exactly as
// VoCat permanentAKAIdentity does: "0<IMSI>@nai.epc.mnc<MNC3>.
// mcc<MCC>.3gppnetwork.org", with a 2-digit MNC left-padded to 3.
// IMSI must be digits, 5-16 long; MCC must be 3 digits; MNC must
// be 2 or 3 digits. No IMSI is ever logged by this package.
func PermanentNAI(imsi, mcc, mnc string) (string, error) {
	imsi = strings.TrimSpace(imsi)
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if len(imsi) < 5 || len(imsi) > 16 {
		return "", errors.New("ike: IMSI length is invalid for EAP-AKA")
	}
	for _, d := range imsi {
		if d < '0' || d > '9' {
			return "", errors.New("ike: IMSI contains a non-digit")
		}
	}
	if len(mcc) != 3 {
		return "", errors.New("ike: MCC must be 3 digits for EAP-AKA")
	}
	for _, d := range mcc {
		if d < '0' || d > '9' {
			return "", errors.New("ike: MCC contains a non-digit")
		}
	}
	if len(mnc) != 2 && len(mnc) != 3 {
		return "", errors.New("ike: MNC must be 2 or 3 digits for EAP-AKA")
	}
	for _, d := range mnc {
		if d < '0' || d > '9' {
			return "", errors.New("ike: MNC contains a non-digit")
		}
	}
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc), nil
}

// payloadWithHeader builds one generic payload: header next, body.
func payloadWithHeader(next byte, body []byte) []byte {
	b := []byte{next, 0, 0, 0}
	b = append(b, body...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

// idBody builds an ID payload body: type byte, 3 reserved bytes,
// then the identity string. IDi uses type 3 (RFC822), IDr uses
// type 2 (FQDN, here carrying the IMS APN, as VoCat does).
func idBody(idType byte, data string) []byte {
	b := []byte{idType, 0, 0, 0}
	return append(b, []byte(data)...)
}

// notifyBody builds a Notify body: protocol 0, SPI size 0,
// notify type, then data.
func notifyBody(notifyType uint16, data []byte) []byte {
	b := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:4], notifyType)
	return append(b, data...)
}

// childSABody builds a minimal child SA proposal body: one ESP
// proposal, ENCR AES_CBC 128, INTEG HMAC_SHA1_96, ESN none.
// It reuses the transform encoding from sainit.go.
func childSABody() []byte {
	transforms := [][]byte{
		transform(3, 1, 12, []byte{0x80, 0x0e, 0x00, 0x80}),
		transform(3, 3, 2, nil),
		transform(0, 5, 0, nil),
	}
	// ESP proposal: number 1, protocol 3 (ESP), SPI size 4,
	// 3 transforms, SPI 4 bytes (zero here; the real SPI is
	// filled by the caller of the full IKE stack).
	propBody := []byte{1, 3, 4, 3, 0, 0, 0, 0}
	for _, t := range transforms {
		propBody = append(propBody, t...)
	}
	proposal := []byte{0, 0, 0, 0}
	proposal = append(proposal, propBody...)
	binary.BigEndian.PutUint16(proposal[2:4], uint16(len(proposal)))
	return proposal
}

// BuildAuth1 returns the state_2 IKE_AUTH(1) payload chain
// (unencrypted, to be wrapped in SK by the full stack):
// IDi -> IDr -> EAP_ONLY -> MOBIKE -> INITIAL_CONTACT ->
// child SA -> TSi -> TSr -> CP.
// TSi/TSr are dual-stack any-traffic selectors (VoCat
// dualStackTrafficSelectors): count 2, then one IPv4 any and one
// IPv6 any selector. CP is a configuration request with no
// attributes here; the real CP attributes (INTERNAL_IP4_ADDRESS
// etc.) are filled by the full stack from the negotiated family.
func BuildAuth1(nai, apn string) []byte {
	if apn == "" {
		apn = "ims"
	}
	ts := func() []byte {
		b := []byte{2, 0, 0, 0}
		b = append(b, 7, 0, 0, 16, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff)
		ipv6 := []byte{8, 0, 0, 40, 0, 0, 0xff, 0xff}
		ipv6 = append(ipv6, make([]byte, 16)...)
		ipv6 = append(ipv6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
		b = append(b, ipv6...)
		return b
	}()
	cpBody := []byte{1} // CFG_REQUEST
	entries := [][2]interface{}{
		{PayloadIDi, idBody(3, nai)},
		{PayloadIDr, idBody(2, apn)},
		{PayloadNotify, notifyBody(NotifyEAPOnlyAuth, nil)},
		{PayloadNotify, notifyBody(NotifyMOBIKESupported, nil)},
		{PayloadNotify, notifyBody(NotifyInitialContact, nil)},
		{PayloadSA, childSABody()},
		{PayloadTSi, ts},
		{PayloadTSr, ts},
		{PayloadCP, cpBody},
	}
	var out []byte
	for i, e := range entries {
		body := e[1].([]byte)
		next := 0
		if i+1 < len(entries) {
			next = entries[i+1][0].(int)
		}
		out = append(out, payloadWithHeader(byte(next), body)...)
	}
	return out
}

// BuildAuthEAP returns the state_3 IKE_AUTH(2) payload chain:
// an EAP response, optionally followed by a DEVICE_IDENTITY
// notify (type 41101) carrying the IMEI/IMEISV data, exactly as
// MDD create_IKE_AUTH_2 does when the ePDG asked for it.
// When deviceIdentity is empty, only the EAP payload is returned.
func BuildAuthEAP(eapResponse, deviceIdentity []byte) []byte {
	if len(deviceIdentity) == 0 {
		return payloadWithHeader(0, eapResponse)
	}
	out := payloadWithHeader(byte(PayloadNotify), eapResponse)
	out = append(out, payloadWithHeader(0, notifyBody(NotifyDeviceIdentity, deviceIdentity))...)
	return out
}

// BuildAuthFinal returns the state_4 IKE_AUTH(3) payload chain:
// a single AUTH payload. authMethod 2 is shared-key MIC, as in
// MDD create_IKE_AUTH_3; authData is the MIC itself, computed
// by the full stack from SK_pi and the IDi transcript.
func BuildAuthFinal(authMethod byte, authData []byte) []byte {
	body := []byte{authMethod, 0, 0, 0}
	body = append(body, authData...)
	return payloadWithHeader(0, body)
}

// ParseAuthChain walks an unencrypted IKE_AUTH payload chain
// (the content of an SK payload after decryption) and returns
// the payload types in order. It reuses Decode's chain-walk
// rules: bad lengths and truncation are errors, not guesses.
func ParseAuthChain(chain []byte) ([]int, error) {
	var types []int
	// The chain is a sequence of generic payloads, but unlike a
	// full IKE packet it has no 28-byte header. Walk it by
	// following each payload's next field, which is stored in
	// the *previous* payload's header in a full packet; here the
	// caller must supply the chain as built by BuildAuth1 etc.,
	// where each header's next field already points forward.
	// To walk it without a header, we read the next field from
	// each header in turn, starting with the first payload's
	// type, which is not stored in the chain itself. Callers
	// therefore use ParseAuthChainWithFirst instead.
	return types, errors.New("ike: use ParseAuthChainWithFirst")
}

// ParseAuthChainWithFirst walks a chain whose first payload type
// is given (e.g. PayloadIDi for AUTH(1), PayloadEAP for AUTH(2),
// PayloadAuth for AUTH(3)) and returns all types in order.
func ParseAuthChainWithFirst(first int, chain []byte) ([]int, error) {
	var types []int
	next := first
	off := 0
	for next != 0 {
		if off+4 > len(chain) {
			return nil, fmt.Errorf("ike: truncated AUTH payload at offset %d", off)
		}
		plen := int(binary.BigEndian.Uint16(chain[off+2 : off+4]))
		if plen < 4 || off+plen > len(chain) {
			return nil, fmt.Errorf("ike: bad AUTH payload length %d at offset %d", plen, off)
		}
		types = append(types, next)
		next = int(chain[off])
		off += plen
	}
	if off != len(chain) {
		return nil, fmt.Errorf("ike: AUTH chain trailing bytes: %d of %d consumed", off, len(chain))
	}
	return types, nil
}

// AuthFailureBeforeEAP reports whether a responder Notify in an
// IKE_AUTH response is an AUTHENTICATION_FAILED (24) that arrived
// before any EAP challenge. Per MDD state_2, that means the AAA
// refused the identity (not provisioned for VoWiFi, or source
// IP/region blocked) and the SIM was never queried.
func AuthFailureBeforeEAP(notifyTypes []uint16, sawEAP bool) bool {
	if sawEAP {
		return false
	}
	for _, t := range notifyTypes {
		if t == NotifyAuthFailed {
			return true
		}
	}
	return false
}
