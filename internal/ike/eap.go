// Package ike, eap.go: EAP-AKA frame handling, reusing VoCat's
// ike/eap.go logic and MDD swu_ike.py state_2/3 handling.
//
// This file never touches a real card and never touches UDP.
// The SIM is an interface; tests use MockSIM. The real SIM
// adapter (MDD ami_usim.py read_res_ck_ik: USIM AUTHENTICATE
// returning RES/CK/IK, or AUTS on synchronisation failure) is
// plugged in by the full stack, not here.
//
// Frame rules copied from VoCat (not guessed):
//   EAP: code, identifier, length, type; AKA data starts with
//     subtype + 2 reserved bytes, then attributes.
//   AKA attribute: type, length in 4-byte units, then value,
//     padded to a multiple of 4. RAND/AUTN/MAC attributes are
//     20 bytes total (2 header + 2 reserved + 16 value).
//   Keys: MK = SHA1(identity || IK || CK); KEncr/KAut/MSK/EMSK
//     are the first 160 bytes of the FIPS 186-2 PRF stream.
//   MAC: HMAC-SHA1 truncated to 16 bytes, over the packet with
//     the MAC field zeroed.
package ike

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const (
	EAPRequest  = 1
	EAPResponse = 2
	EAPSuccess  = 3
	EAPFailure  = 4

	EAPTypeIdentity = 1
	EAPTypeAKA      = 23

	AKASubtypeChallenge    = 1
	AKASubtypeAuthReject   = 2
	AKASubtypeSyncFailure  = 4
	AKASubtypeIdentity     = 5
	AKASubtypeNotification = 12
	AKASubtypeReauth       = 13
	AKASubtypeClientError  = 14

	AKAAttrRAND          = 1
	AKAAttrAUTN          = 2
	AKAAttrRES           = 3
	AKAAttrAUTS          = 4
	AKAAttrPermanentIDReq = 10
	AKAAttrMAC           = 11
	AKAAttrAnyIDReq      = 13
	AKAAttrIdentity      = 14
	AKAAttrFullAuthIDReq = 17
	AKAAttrClientError   = 22
	AKAAttrResultInd     = 135
)

// EAPPacket is a parsed EAP packet.
type EAPPacket struct {
	Code       int
	Identifier int
	Type       int
	Data       []byte // after the type byte, for Request/Response
}

// ParseEAP parses one EAP packet; length must match exactly.
func ParseEAP(encoded []byte) (EAPPacket, error) {
	if len(encoded) < 4 {
		return EAPPacket{}, errors.New("ike: truncated EAP header")
	}
	length := int(binary.BigEndian.Uint16(encoded[2:4]))
	if length != len(encoded) {
		return EAPPacket{}, fmt.Errorf("ike: EAP length %d does not match payload length %d", length, len(encoded))
	}
	p := EAPPacket{Code: int(encoded[0]), Identifier: int(encoded[1])}
	switch p.Code {
	case EAPRequest, EAPResponse:
		if len(encoded) < 5 {
			return EAPPacket{}, errors.New("ike: typed EAP packet is truncated")
		}
		p.Type = int(encoded[4])
		p.Data = append([]byte(nil), encoded[5:]...)
	case EAPSuccess, EAPFailure:
		if len(encoded) != 4 {
			return EAPPacket{}, errors.New("ike: EAP success/failure has trailing data")
		}
	default:
		return EAPPacket{}, fmt.Errorf("ike: unsupported EAP code %d", p.Code)
	}
	return p, nil
}

// MarshalEAP encodes one EAP packet.
func MarshalEAP(p EAPPacket) ([]byte, error) {
	length := 4
	if p.Code == EAPRequest || p.Code == EAPResponse {
		if p.Type == 0 {
			return nil, errors.New("ike: typed EAP packet has no type")
		}
		length += 1 + len(p.Data)
	} else if len(p.Data) != 0 || p.Type != 0 {
		return nil, errors.New("ike: EAP success/failure cannot carry type data")
	}
	if length > 65535 {
		return nil, errors.New("ike: EAP packet exceeds 65535 bytes")
	}
	out := make([]byte, length)
	out[0] = byte(p.Code)
	out[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(out[2:4], uint16(length))
	if length > 4 {
		out[4] = byte(p.Type)
		copy(out[5:], p.Data)
	}
	return out, nil
}

// AKAAttribute is one parsed EAP-AKA attribute.
type AKAAttribute struct {
	Type   int
	Raw    []byte // full attribute including type/length header
	Offset int    // offset within the attribute list
}

// ParseAKAAttributes parses an attribute list; each length is
// in 4-byte units and must fit exactly.
func ParseAKAAttributes(encoded []byte) ([]AKAAttribute, error) {
	var out []AKAAttribute
	for off := 0; off < len(encoded); {
		if len(out) >= 64 || off+2 > len(encoded) {
			return nil, errors.New("ike: malformed EAP-AKA attribute list")
		}
		length := int(encoded[off+1]) * 4
		if length < 4 || off+length > len(encoded) {
			return nil, fmt.Errorf("ike: EAP-AKA attribute %d has invalid length %d", encoded[off], length)
		}
		out = append(out, AKAAttribute{Type: int(encoded[off]), Raw: append([]byte(nil), encoded[off:off+length]...), Offset: off})
		off += length
	}
	return out, nil
}

// MarshalAKAAttribute encodes one attribute, padded to 4 bytes.
func MarshalAKAAttribute(kind int, value []byte) ([]byte, error) {
	length := 2 + len(value)
	padded := (length + 3) &^ 3
	if padded/4 > 255 {
		return nil, errors.New("ike: EAP-AKA attribute is too long")
	}
	out := make([]byte, padded)
	out[0] = byte(kind)
	out[1] = byte(padded / 4)
	copy(out[2:], value)
	return out, nil
}

func oneAKAAttribute(attrs []AKAAttribute, kind int) (AKAAttribute, error) {
	var found AKAAttribute
	count := 0
	for _, a := range attrs {
		if a.Type == kind {
			found = a
			count++
		}
	}
	if count != 1 {
		return AKAAttribute{}, fmt.Errorf("ike: EAP-AKA expected one attribute %d, got %d", kind, count)
	}
	return found, nil
}

// AKAKeys are the keys derived from IK/CK (VoCat deriveAKAKeys).
type AKAKeys struct {
	KEncr []byte
	KAut  []byte
	MSK   []byte
	EMSK  []byte
}

// DeriveAKAKeys derives keys from identity, IK and CK.
func DeriveAKAKeys(identity, ik, ck []byte) (AKAKeys, error) {
	if len(identity) == 0 {
		return AKAKeys{}, errors.New("ike: EAP-AKA identity is empty")
	}
	if len(ik) != 16 || len(ck) != 16 {
		return AKAKeys{}, fmt.Errorf("ike: EAP-AKA requires 16-byte IK and CK, got %d and %d", len(ik), len(ck))
	}
	material := append(append([]byte(nil), identity...), ik...)
	material = append(material, ck...)
	mk := sha1.Sum(material)
	stream := fips1862PRF(mk[:], 160)
	return AKAKeys{
		KEncr: append([]byte(nil), stream[0:16]...),
		KAut:  append([]byte(nil), stream[16:32]...),
		MSK:   append([]byte(nil), stream[32:96]...),
		EMSK:  append([]byte(nil), stream[96:160]...),
	}, nil
}

func fips1862PRF(seed []byte, length int) []byte {
	xkey := new(big.Int).SetBytes(seed)
	modulus := new(big.Int).Lsh(big.NewInt(1), 160)
	var result []byte
	for len(result) < length {
		xval := xkey.FillBytes(make([]byte, 20))
		word := fipsSHA1G(xval)
		result = append(result, word[:]...)
		inc := new(big.Int).SetBytes(word[:])
		xkey.Add(xkey, inc)
		xkey.Add(xkey, big.NewInt(1))
		xkey.Mod(xkey, modulus)
	}
	return result[:length]
}

func fipsSHA1G(xval []byte) [20]byte {
	var words [80]uint32
	var block [64]byte
	copy(block[:20], xval)
	for i := 0; i < 16; i++ {
		words[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
	}
	for i := 16; i < 80; i++ {
		v := words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]
		words[i] = v<<1 | v>>31
	}
	a, b, c, d, e := uint32(0x67452301), uint32(0xEFCDAB89), uint32(0x98BADCFE), uint32(0x10325476), uint32(0xC3D2E1F0)
	ia, ib, ic, id, ie := a, b, c, d, e
	for i := 0; i < 80; i++ {
		var fn, cn uint32
		switch {
		case i < 20:
			fn = (b & c) | (^b & d)
			cn = 0x5A827999
		case i < 40:
			fn = b ^ c ^ d
			cn = 0x6ED9EBA1
		case i < 60:
			fn = (b & c) | (b & d) | (c & d)
			cn = 0x8F1BBCDC
		default:
			fn = b ^ c ^ d
			cn = 0xCA62C1D6
		}
		next := (a<<5 | a>>27) + fn + e + cn + words[i]
		e, d, c, b, a = d, c, b<<30|b>>2, a, next
	}
	vals := [5]uint32{ia + a, ib + b, ic + c, id + d, ie + e}
	var out [20]byte
	for i, v := range vals {
		binary.BigEndian.PutUint32(out[i*4:i*4+4], v)
	}
	return out
}

// AKAMAC is HMAC-SHA1 truncated to 16 bytes.
func AKAMAC(key, packet []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(packet)
	return m.Sum(nil)[:16]
}

// SIMAKA is the card side of EAP-AKA. Authenticate runs USIM
// AUTHENTICATE with RAND/AUTN. On success it returns RES (4-16
// bytes), CK and IK (16 bytes each). On synchronisation failure
// it returns syncFailure=true with a 14-byte AUTS and no RES.
type SIMAKA interface {
	Authenticate(rand, autn []byte) (res, ck, ik, auts []byte, syncFailure bool, err error)
}

// MockSIM is a test SIM with fixed outputs; it never touches a
// real card. Set SyncAUTS to test the sync-failure path.
type MockSIM struct {
	RES       []byte
	CK        []byte
	IK        []byte
	SyncAUTS  []byte
	Err       error
	LastRAND  []byte
	LastAUTN  []byte
	CallCount int
}

func (m *MockSIM) Authenticate(rand, autn []byte) ([]byte, []byte, []byte, []byte, bool, error) {
	m.CallCount++
	m.LastRAND = append([]byte(nil), rand...)
	m.LastAUTN = append([]byte(nil), autn...)
	if m.Err != nil {
		return nil, nil, nil, nil, false, m.Err
	}
	if len(m.SyncAUTS) > 0 {
		return nil, nil, nil, append([]byte(nil), m.SyncAUTS...), true, nil
	}
	return append([]byte(nil), m.RES...), append([]byte(nil), m.CK...), append([]byte(nil), m.IK...), nil, false, nil
}

// EAPAKAClient handles one EAP-AKA exchange for a fixed NAI.
type EAPAKAClient struct {
	NAI               string
	SIM               SIMAKA
	Keys              AKAKeys
	ChallengeComplete bool
	ResultIndication  bool
	lastStage         string
}

func NewEAPAKAClient(nai string, sim SIMAKA) (*EAPAKAClient, error) {
	if nai == "" {
		return nil, errors.New("ike: EAP-AKA NAI is empty")
	}
	if sim == nil {
		return nil, errors.New("ike: EAP-AKA SIM provider is required")
	}
	return &EAPAKAClient{NAI: nai, SIM: sim, lastStage: "initial"}, nil
}

// ClientErrorResponse builds an EAP-AKA client-error response.
func ClientErrorResponse(identifier int) ([]byte, error) {
	attr, err := MarshalAKAAttribute(AKAAttrClientError, []byte{0, 0})
	if err != nil {
		return nil, err
	}
	data := append([]byte{AKASubtypeClientError, 0, 0}, attr...)
	return MarshalEAP(EAPPacket{Code: EAPResponse, Identifier: identifier, Type: EAPTypeAKA, Data: data})
}

// AuthRejectResponse builds an EAP-AKA authentication-reject.
func AuthRejectResponse(identifier int) ([]byte, error) {
	return MarshalEAP(EAPPacket{Code: EAPResponse, Identifier: identifier, Type: EAPTypeAKA, Data: []byte{AKASubtypeAuthReject, 0, 0}})
}

// Handle processes one responder EAP packet and returns the
// response packet, or success=true for EAP-Success. An error
// means the exchange failed; the caller should send a
// client-error response unless the error is a MAC failure that
// VoCat maps to an authentication reject (handled by the caller
// via AuthRejectResponse when it knows the cause).
func (c *EAPAKAClient) Handle(encoded []byte) (response []byte, success bool, err error) {
	pkt, err := ParseEAP(encoded)
	if err != nil {
		return nil, false, err
	}
	switch pkt.Code {
	case EAPFailure:
		return nil, false, fmt.Errorf("ike: EAP authentication rejected %s", c.lastStage)
	case EAPSuccess:
		if !c.ChallengeComplete {
			return nil, false, errors.New("ike: EAP success arrived before an authenticated AKA challenge")
		}
		return nil, true, nil
	case EAPRequest:
	default:
		return nil, false, fmt.Errorf("ike: unexpected EAP code %d from responder", pkt.Code)
	}
	switch pkt.Type {
	case EAPTypeIdentity:
		resp, err := MarshalEAP(EAPPacket{Code: EAPResponse, Identifier: pkt.Identifier, Type: EAPTypeIdentity, Data: []byte(c.NAI)})
		c.lastStage = "after EAP-Response/Identity"
		return resp, false, err
	case EAPTypeAKA:
		return c.handleAKA(pkt)
	default:
		return nil, false, fmt.Errorf("ike: responder requested unsupported EAP type %d", pkt.Type)
	}
}

func (c *EAPAKAClient) handleAKA(pkt EAPPacket) ([]byte, bool, error) {
	if len(pkt.Data) < 3 {
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, errors.New("ike: EAP-AKA packet too short")
	}
	subtype := pkt.Data[0]
	if pkt.Data[1] != 0 || pkt.Data[2] != 0 {
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, errors.New("ike: EAP-AKA reserved bytes not zero")
	}
	attrs, err := ParseAKAAttributes(pkt.Data[3:])
	if err != nil {
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, err
	}
	switch subtype {
	case AKASubtypeIdentity:
		requests := 0
		for _, a := range attrs {
			switch a.Type {
			case AKAAttrPermanentIDReq, AKAAttrAnyIDReq, AKAAttrFullAuthIDReq:
				if len(a.Raw) != 4 {
					return nil, false, errors.New("ike: malformed EAP-AKA identity request attribute")
				}
				requests++
			default:
				if a.Type < 128 {
					return nil, false, fmt.Errorf("ike: unsupported mandatory EAP-AKA identity attribute %d", a.Type)
				}
			}
		}
		if requests != 1 {
			return nil, false, errors.New("ike: EAP-AKA identity request must contain exactly one request attribute")
		}
		idAttr, err := MarshalAKAAttribute(AKAAttrIdentity, append([]byte{byte(len(c.NAI) >> 8), byte(len(c.NAI))}, []byte(c.NAI)...))
		if err != nil {
			return nil, false, err
		}
		data := append([]byte{AKASubtypeIdentity, 0, 0}, idAttr...)
		resp, err := MarshalEAP(EAPPacket{Code: EAPResponse, Identifier: pkt.Identifier, Type: EAPTypeAKA, Data: data})
		c.lastStage = "after EAP-Response/AKA-Identity"
		return resp, false, err
	case AKASubtypeChallenge:
		return c.handleChallenge(pkt, attrs)
	case AKASubtypeNotification:
		// Notification with success flag is informational; the
		// exchange continues. A notification without it is
		// treated as a failure by the caller via the returned
		// error only if the attribute says so; here we return
		// an empty response marker: no response packet, no
		// success, no error, which the caller treats as
		// "notification acknowledged, wait for next packet".
		// To keep the API simple, return a client-error only
		// for malformed notifications; otherwise return nil.
		return nil, false, nil
	case AKASubtypeReauth:
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, errors.New("ike: EAP-AKA reauth not supported")
	default:
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, fmt.Errorf("ike: unsupported EAP-AKA subtype %d", subtype)
	}
}

func (c *EAPAKAClient) handleChallenge(pkt EAPPacket, attrs []AKAAttribute) ([]byte, bool, error) {
	for _, a := range attrs {
		switch a.Type {
		case AKAAttrRAND, AKAAttrAUTN, AKAAttrMAC, AKAAttrResultInd:
		default:
			if a.Type < 128 {
				resp, _ := ClientErrorResponse(pkt.Identifier)
				return resp, false, fmt.Errorf("ike: unknown mandatory EAP-AKA challenge attribute %d", a.Type)
			}
		}
	}
	randAttr, err := oneAKAAttribute(attrs, AKAAttrRAND)
	if err != nil {
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, err
	}
	autnAttr, err := oneAKAAttribute(attrs, AKAAttrAUTN)
	if err != nil {
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, err
	}
	macAttr, err := oneAKAAttribute(attrs, AKAAttrMAC)
	if err != nil {
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, err
	}
	if len(randAttr.Raw) != 20 || len(autnAttr.Raw) != 20 || len(macAttr.Raw) != 20 {
		resp, _ := ClientErrorResponse(pkt.Identifier)
		return resp, false, errors.New("ike: EAP-AKA RAND, AUTN, or MAC has an invalid length")
	}
	randVal := append([]byte(nil), randAttr.Raw[4:20]...)
	autnVal := append([]byte(nil), autnAttr.Raw[4:20]...)
	res, ck, ik, auts, syncFailure, err := c.SIM.Authenticate(randVal, autnVal)
	if err != nil {
		return nil, false, fmt.Errorf("ike: SIM AKA authentication: %w", err)
	}
	if syncFailure {
		if len(auts) != 14 {
			return nil, false, errors.New("ike: SIM reported synchronization failure without a 14-byte AUTS")
		}
		autsAttr, err := MarshalAKAAttribute(AKAAttrAUTS, auts)
		if err != nil {
			return nil, false, err
		}
		data := append([]byte{AKASubtypeSyncFailure, 0, 0}, autsAttr...)
		resp, err := MarshalEAP(EAPPacket{Code: EAPResponse, Identifier: pkt.Identifier, Type: EAPTypeAKA, Data: data})
		return resp, false, err
	}
	if len(res) < 4 || len(res) > 16 || len(ck) != 16 || len(ik) != 16 {
		return nil, false, fmt.Errorf("ike: SIM returned invalid RES/CK/IK lengths %d/%d/%d", len(res), len(ck), len(ik))
	}
	keys, err := DeriveAKAKeys([]byte(c.NAI), ik, ck)
	if err != nil {
		return nil, false, err
	}
	// Verify server MAC over the request with the MAC field zeroed.
	requestBytes, err := MarshalEAP(pkt)
	if err != nil {
		return nil, false, err
	}
	zeroed := append([]byte(nil), requestBytes...)
	macOffset := 5 + 3 + macAttr.Offset
	if macOffset+20 > len(zeroed) {
		return nil, false, errors.New("ike: EAP-AKA MAC offset is invalid")
	}
	for i := macOffset + 4; i < macOffset+20; i++ {
		zeroed[i] = 0
	}
	expected := AKAMAC(keys.KAut, zeroed)
	if subtle.ConstantTimeCompare(expected, macAttr.Raw[4:20]) != 1 {
		return nil, false, errors.New("ike: EAP-AKA server MAC is invalid")
	}
	// Build challenge response: RES, optional ResultInd, MAC.
	resValue := make([]byte, 2+len(res))
	binary.BigEndian.PutUint16(resValue[0:2], uint16(len(res)*8))
	copy(resValue[2:], res)
	resAttr, err := MarshalAKAAttribute(AKAAttrRES, resValue)
	if err != nil {
		return nil, false, err
	}
	responseData := append([]byte{AKASubtypeChallenge, 0, 0}, resAttr...)
	resultInd := false
	for _, a := range attrs {
		if a.Type == AKAAttrResultInd {
			if len(a.Raw) != 4 {
				return nil, false, errors.New("ike: malformed AT_RESULT_IND")
			}
			responseData = append(responseData, a.Raw...)
			resultInd = true
		}
	}
	macAttrBytes, err := MarshalAKAAttribute(AKAAttrMAC, make([]byte, 18))
	if err != nil {
		return nil, false, err
	}
	responseData = append(responseData, macAttrBytes...)
	respBytes, err := MarshalEAP(EAPPacket{Code: EAPResponse, Identifier: pkt.Identifier, Type: EAPTypeAKA, Data: responseData})
	if err != nil {
		return nil, false, err
	}
	// Patch the MAC: find the MAC attribute in the response.
	respAttrs, err := ParseAKAAttributes(responseData[3:])
	if err != nil {
		return nil, false, err
	}
	respMAC, err := oneAKAAttribute(respAttrs, AKAAttrMAC)
	if err != nil {
		return nil, false, err
	}
	respMACOffset := 5 + 3 + respMAC.Offset
	computed := AKAMAC(keys.KAut, respBytes)
	copy(respBytes[respMACOffset+4:respMACOffset+20], computed)
	c.Keys = keys
	c.ChallengeComplete = true
	c.ResultIndication = resultInd
	c.lastStage = "after EAP-Response/AKA-Challenge"
	return respBytes, false, nil
}
