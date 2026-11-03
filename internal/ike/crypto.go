// Package ike, crypto.go: IKEv2 SA key derivation, SK payload
// protection, and AUTH MIC computation (RFC 7296 sections 2.13,
// 2.14, 2.15 and 3.14), adapted to this module's existing
// sainit.go / auth.go layout.
//
// The wire layout here is deliberately the one already used by
// this package: a 28-byte header as a []byte (as in
// BuildSAInit), ID payload bodies as returned by idBody in
// auth.go (type byte + 3 reserved bytes + identity, without the
// 4-byte generic payload header), and AUTH payloads built by
// BuildAuthFinal. No function here touches UDP or a card, so all
// of it is testable in this container.
//
// Key derivation (RFC 7296 2.14):
//
//	SKEYSEED = prf(Ni | Nr, g^ir)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	  = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//
// where SK_d / SK_pi / SK_pr are one PRF output long, SK_ai /
// SK_ar are one integrity-key long, and SK_ei / SK_er are one
// encryption-key long.
//
// SK payload protection: AES-CBC over the inner payload chain
// plus an integrity checksum truncated to 12 bytes (HMAC-SHA1-96)
// or 16 bytes (HMAC-SHA256-128). Padding is PKCS#7, as specified
// for this step, on both encrypt and decrypt: the last byte is
// the pad length and exactly that many trailing bytes are pad.
// Integrity is verified (constant-time) before any decryption,
// so a tampered packet is rejected on the MAC, not on padding.
// Note for a later live-peer step: RFC 7296's own SK padding
// counts the pad bytes plus a separate length byte, so a peer
// implementing strict RFC framing would strip one byte more
// than PKCS#7; check that framing before wiring this to a real
// ePDG response parser.
//
// AUTH MIC (RFC 7296 2.15, EAP form 2.16):
//
//	SignedOctets (initiator) = SA_INIT request | Nr | prf(SK_pi, IDi body)
//	SignedOctets (responder) = SA_INIT response | Ni | prf(SK_pr, IDr body)
//	AUTH = prf(prf(MSK, "Key Pad for IKEv2"), SignedOctets)
//
// with method 2 (shared-key MIC). For non-EAP shared-key AUTH
// the same formula applies with the shared secret in place of
// the MSK.
package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
)

// Transform IDs for the negotiated IKE SA (RFC 7296 3.3).
const (
	// PRF IDs.
	PRFHMACSHA1   = 2
	PRFHMACSHA256 = 5
	// Integrity IDs.
	IntegrityHMACSHA1_96    = 2
	IntegrityHMACSHA256_128 = 12
	// Encryption ID (the pinned proposal in sainit.go uses 12).
	EncryptionAESCBC = 12
	// DH group IDs.
	DHMODP1024 = 2
	// AUTH method for shared-key MIC (auth.go uses literal 2).
	AuthMethodSharedKeyMIC = 2
)

// KeyPadForIKEv2 is the fixed PRF input for EAP AUTH keys.
const KeyPadForIKEv2 = "Key Pad for IKEv2"

// Suite is the negotiated IKE SA transform set that key
// derivation and SK protection use. EncryptionBits is 128 or
// 256; the encryption transform itself is always AES-CBC, as in
// the pinned proposal.
type Suite struct {
	PRFID          int
	IntegrityID    int
	EncryptionBits int
}

// PinnedSuite returns the suite matching PinnedSA in sainit.go:
// PRF HMAC-SHA1, integrity HMAC-SHA1-96, AES-CBC 128, DH MODP1024.
func PinnedSuite() Suite {
	_, prfID, integID, _, keyLen := PinnedSA()
	return Suite{PRFID: prfID, IntegrityID: integID, EncryptionBits: keyLen}
}

func (s Suite) prfHash() (func() hash.Hash, int, error) {
	switch s.PRFID {
	case PRFHMACSHA1:
		return sha1.New, sha1.Size, nil
	case PRFHMACSHA256:
		return sha256.New, sha256.Size, nil
	default:
		return nil, 0, fmt.Errorf("ike: unsupported PRF id %d", s.PRFID)
	}
}

func (s Suite) integrityLengths() (keyLen, checksumLen int, err error) {
	switch s.IntegrityID {
	case IntegrityHMACSHA1_96:
		return sha1.Size, 12, nil
	case IntegrityHMACSHA256_128:
		return sha256.Size, 16, nil
	default:
		return 0, 0, fmt.Errorf("ike: unsupported integrity id %d", s.IntegrityID)
	}
}

func (s Suite) encryptionKeyLength() (int, error) {
	switch s.EncryptionBits {
	case 128, 256:
		return s.EncryptionBits / 8, nil
	default:
		return 0, fmt.Errorf("ike: unsupported AES key length %d bits", s.EncryptionBits)
	}
}

// PRF is the suite's pseudorandom function: HMAC with the
// suite's hash, keyed by key, over data.
func PRF(s Suite, key, data []byte) ([]byte, error) {
	newHash, _, err := s.prfHash()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(newHash, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// PRFPlus is RFC 7296 2.13 prf+: T(1) = prf(key, seed | 0x01),
// T(i) = prf(key, T(i-1) | seed | i), concatenated and truncated
// to length bytes.
func PRFPlus(s Suite, key, seed []byte, length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("ike: PRF+ length is negative")
	}
	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		if counter == 0 {
			return nil, errors.New("ike: PRF+ output is too long")
		}
		input := make([]byte, 0, len(prev)+len(seed)+1)
		input = append(input, prev...)
		input = append(input, seed...)
		input = append(input, counter)
		block, err := PRF(s, key, input)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
		prev = block
	}
	return out[:length], nil
}

// SKKeys holds the derived IKE SA keys plus the SKEYSEED they
// came from. Slices are copies; mutating one does not alias the
// PRF+ stream.
type SKKeys struct {
	SKEYSEED []byte
	SKd      []byte
	SKai     []byte
	SKar     []byte
	SKei     []byte
	SKer     []byte
	SKpi     []byte
	SKpr     []byte
}

func modp1024PrimeInt() (*big.Int, error) {
	p, ok := new(big.Int).SetString(modp1024Prime, 16)
	if !ok {
		return nil, errors.New("ike: MODP1024 prime constant is invalid")
	}
	return p, nil
}

func modp1024Size() int {
	// The prime in sainit.go is 128 bytes; keep this in sync by
	// deriving it from the constant rather than hard-coding.
	p, err := modp1024PrimeInt()
	if err != nil {
		return 128
	}
	return len(p.Bytes())
}

// MODP1024Public returns the DH public value 2^priv mod p,
// padded to 128 bytes. priv must be in [2, p-2]; small values
// such as 2 and 3 are valid inputs and give the known answers
// 4 and 8, which the tests use.
func MODP1024Public(private []byte) ([]byte, error) {
	p, err := modp1024PrimeInt()
	if err != nil {
		return nil, err
	}
	priv := new(big.Int).SetBytes(private)
	if len(private) == 0 || priv.Cmp(big.NewInt(2)) < 0 || priv.Cmp(new(big.Int).Sub(p, big.NewInt(2))) > 0 {
		return nil, errors.New("ike: MODP1024 private value is out of range")
	}
	pub := new(big.Int).Exp(big.NewInt(2), priv, p)
	return pub.FillBytes(make([]byte, modp1024Size())), nil
}

// MODP1024Shared returns the DH shared secret peer^priv mod p,
// padded to 128 bytes. It rejects a peer value outside
// [2, p-2] and a trivial (0 or 1) result, which would make the
// derived keys predictable.
func MODP1024Shared(private, peerPublic []byte) ([]byte, error) {
	p, err := modp1024PrimeInt()
	if err != nil {
		return nil, err
	}
	priv := new(big.Int).SetBytes(private)
	if len(private) == 0 || priv.Cmp(big.NewInt(2)) < 0 || priv.Cmp(new(big.Int).Sub(p, big.NewInt(2))) > 0 {
		return nil, errors.New("ike: MODP1024 private value is out of range")
	}
	if len(peerPublic) != modp1024Size() {
		return nil, fmt.Errorf("ike: MODP1024 peer value length %d, want %d", len(peerPublic), modp1024Size())
	}
	peer := new(big.Int).SetBytes(peerPublic)
	if peer.Cmp(big.NewInt(2)) < 0 || peer.Cmp(new(big.Int).Sub(p, big.NewInt(2))) > 0 {
		return nil, errors.New("ike: MODP1024 peer value is out of range")
	}
	shared := new(big.Int).Exp(peer, priv, p)
	if shared.Sign() == 0 || shared.Cmp(big.NewInt(1)) == 0 {
		return nil, errors.New("ike: MODP1024 shared secret is trivial")
	}
	return shared.FillBytes(make([]byte, modp1024Size())), nil
}

// DHExchange is one side of a MODP1024 exchange: it owns a
// private value (never exposed) and the public value to send in
// the KE payload.
type DHExchange struct {
	Public  []byte
	private *big.Int
}

// NewDHExchange generates a MODP1024 private value from random
// (crypto/rand when nil) and computes its public value. The
// private value is a 32-byte sample reduced into [2, p-3], the
// same width dhPublic in sainit.go uses for its one-shot public
// value, but here the private value is retained so Shared can
// run after the responder's KE arrives.
func NewDHExchange(random io.Reader) (*DHExchange, error) {
	if random == nil {
		random = rand.Reader
	}
	p, err := modp1024PrimeInt()
	if err != nil {
		return nil, err
	}
	sample := make([]byte, 32)
	if _, err := io.ReadFull(random, sample); err != nil {
		return nil, fmt.Errorf("ike: generate DH private value: %w", err)
	}
	priv := new(big.Int).SetBytes(sample)
	priv.Mod(priv, new(big.Int).Sub(p, big.NewInt(3)))
	priv.Add(priv, big.NewInt(2))
	pub := new(big.Int).Exp(big.NewInt(2), priv, p)
	return &DHExchange{
		Public:  pub.FillBytes(make([]byte, modp1024Size())),
		private: priv,
	}, nil
}

// Shared computes the shared secret against the peer's KE value.
func (d *DHExchange) Shared(peerPublic []byte) ([]byte, error) {
	if d == nil || d.private == nil {
		return nil, errors.New("ike: DH exchange is not initialized")
	}
	return MODP1024Shared(d.private.Bytes(), peerPublic)
}

// DeriveKeys runs RFC 7296 2.14 from a DH shared secret, the two
// nonces, and the two SPIs. It returns the SKEYSEED inside
// SKKeys so callers and tests can check it against a direct
// prf(Ni|Nr, shared) computation.
func DeriveKeys(s Suite, sharedSecret, ni, nr []byte, spiI, spiR [8]byte) (SKKeys, error) {
	prfLen, err := func() (int, error) {
		_, n, err := s.prfHash()
		return n, err
	}()
	if err != nil {
		return SKKeys{}, err
	}
	encLen, err := s.encryptionKeyLength()
	if err != nil {
		return SKKeys{}, err
	}
	integLen, _, err := s.integrityLengths()
	if err != nil {
		return SKKeys{}, err
	}
	if len(sharedSecret) == 0 || len(ni) == 0 || len(nr) == 0 {
		return SKKeys{}, errors.New("ike: key derivation needs a shared secret and both nonces")
	}
	nonceKey := append(append([]byte(nil), ni...), nr...)
	skeyseed, err := PRF(s, nonceKey, sharedSecret)
	if err != nil {
		return SKKeys{}, err
	}
	seed := make([]byte, 0, len(ni)+len(nr)+16)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	seed = append(seed, spiI[:]...)
	seed = append(seed, spiR[:]...)
	total := prfLen + integLen*2 + encLen*2 + prfLen*2
	stream, err := PRFPlus(s, skeyseed, seed, total)
	if err != nil {
		return SKKeys{}, err
	}
	take := func(n int) []byte {
		v := append([]byte(nil), stream[:n]...)
		stream = stream[n:]
		return v
	}
	return SKKeys{
		SKEYSEED: skeyseed,
		SKd:      take(prfLen),
		SKai:     take(integLen),
		SKar:     take(integLen),
		SKei:     take(encLen),
		SKer:     take(encLen),
		SKpi:     take(prfLen),
		SKpr:     take(prfLen),
	}, nil
}

// IntegrityMAC returns the truncated integrity checksum for a
// packet without its checksum field: HMAC-SHA1 truncated to 12
// bytes, or HMAC-SHA256 truncated to 16 bytes.
func IntegrityMAC(s Suite, key, packetWithoutChecksum []byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch s.IntegrityID {
	case IntegrityHMACSHA1_96:
		newHash = sha1.New
	case IntegrityHMACSHA256_128:
		newHash = sha256.New
	default:
		return nil, fmt.Errorf("ike: unsupported integrity id %d", s.IntegrityID)
	}
	_, checksumLen, err := s.integrityLengths()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(newHash, key)
	mac.Write(packetWithoutChecksum)
	return mac.Sum(nil)[:checksumLen], nil
}

// EncryptCBC encrypts with AES-CBC and PKCS#7 padding: a full
// extra block is added when the plaintext is already block
// aligned, and every pad byte equals the pad length.
func EncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ike: initialize AES: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("ike: AES IV length %d, want %d", len(iv), block.BlockSize())
	}
	padLen := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := append(append([]byte(nil), plaintext...), make([]byte, padLen)...)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// DecryptCBC decrypts AES-CBC and strips PKCS#7 padding,
// rejecting a bad length, a pad length outside 1..16, or pad
// bytes that do not all equal the pad length.
func DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ike: initialize AES: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("ike: AES IV length %d, want %d", len(iv), block.BlockSize())
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("ike: AES ciphertext is not block aligned")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	padLen := int(plain[len(plain)-1])
	if padLen < 1 || padLen > block.BlockSize() || padLen > len(plain) {
		return nil, errors.New("ike: AES PKCS#7 padding length is invalid")
	}
	for i := len(plain) - padLen; i < len(plain); i++ {
		if int(plain[i]) != padLen {
			return nil, errors.New("ike: AES PKCS#7 padding bytes are invalid")
		}
	}
	return plain[:len(plain)-padLen], nil
}

// EncryptSKPacket wraps an inner payload chain (for example the
// output of BuildAuth1) in an SK payload inside a full IKE
// packet. header must be 28 bytes; its NextPayload and Length
// fields are overwritten (NextPayload = PayloadSK, Length =
// packet length). random supplies the 16-byte IV (crypto/rand
// when nil). encKey/integKey are the sender's SK_ei/SK_ai (or
// SK_er/SK_ar for a responder packet).
func EncryptSKPacket(header []byte, firstPayload byte, plaintext []byte, s Suite, encKey, integKey []byte, random io.Reader) ([]byte, error) {
	if len(header) != 28 {
		return nil, fmt.Errorf("ike: SK header length %d, want 28", len(header))
	}
	if random == nil {
		random = rand.Reader
	}
	_, checksumLen, err := s.integrityLengths()
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, fmt.Errorf("ike: generate SK IV: %w", err)
	}
	ciphertext, err := EncryptCBC(encKey, iv, plaintext)
	if err != nil {
		return nil, err
	}
	skLen := 4 + len(iv) + len(ciphertext) + checksumLen
	if skLen > 65535 {
		return nil, errors.New("ike: SK payload exceeds 65535 bytes")
	}
	body := make([]byte, skLen)
	body[0] = firstPayload
	binary.BigEndian.PutUint16(body[2:4], uint16(skLen))
	copy(body[4:], iv)
	copy(body[4+len(iv):], ciphertext)
	hdr := append([]byte(nil), header...)
	hdr[16] = byte(PayloadSK)
	if hdr[17] == 0 {
		hdr[17] = 0x20
	}
	binary.BigEndian.PutUint32(hdr[24:28], uint32(28+skLen))
	packet := append(hdr, body...)
	checksum, err := IntegrityMAC(s, integKey, packet[:len(packet)-checksumLen])
	if err != nil {
		return nil, err
	}
	copy(packet[len(packet)-checksumLen:], checksum)
	return packet, nil
}

// DecryptSKPacket verifies the integrity checksum (constant
// time) and then decrypts an SK packet produced by
// EncryptSKPacket or by a peer. It returns the first inner
// payload type (the SK payload's first byte), the decrypted
// inner chain, and a copy of the 28-byte header.
func DecryptSKPacket(packet []byte, s Suite, encKey, integKey []byte) (byte, []byte, []byte, error) {
	if len(packet) < 28 {
		return 0, nil, nil, errors.New("ike: SK packet is too short")
	}
	if binary.BigEndian.Uint32(packet[24:28]) != uint32(len(packet)) {
		return 0, nil, nil, errors.New("ike: SK header length does not match packet length")
	}
	if int(packet[16]) != PayloadSK {
		return 0, nil, nil, fmt.Errorf("ike: packet next payload %d is not SK", packet[16])
	}
	_, checksumLen, err := s.integrityLengths()
	if err != nil {
		return 0, nil, nil, err
	}
	body := packet[28:]
	if len(body) < 4 {
		return 0, nil, nil, errors.New("ike: SK payload is truncated")
	}
	if int(binary.BigEndian.Uint16(body[2:4])) != len(body) {
		return 0, nil, nil, errors.New("ike: SK payload length does not match body length")
	}
	if len(body) < 4+aes.BlockSize+aes.BlockSize+checksumLen {
		return 0, nil, nil, errors.New("ike: SK payload is too short for IV, ciphertext and checksum")
	}
	expected, err := IntegrityMAC(s, integKey, packet[:len(packet)-checksumLen])
	if err != nil {
		return 0, nil, nil, err
	}
	if subtle.ConstantTimeCompare(packet[len(packet)-checksumLen:], expected) != 1 {
		return 0, nil, nil, errors.New("ike: SK integrity checksum mismatch")
	}
	iv := body[4 : 4+aes.BlockSize]
	ciphertext := body[4+aes.BlockSize : len(body)-checksumLen]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return 0, nil, nil, errors.New("ike: SK ciphertext is not block aligned")
	}
	plain := make([]byte, len(ciphertext))
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("ike: initialize AES: %w", err)
	}
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	// PKCS#7 framing, matching EncryptSKPacket via EncryptCBC:
	// the last byte is the pad length and exactly that many
	// trailing bytes are padding.
	padLen := int(plain[len(plain)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(plain) {
		return 0, nil, nil, errors.New("ike: SK padding length is invalid")
	}
	return body[0], plain[:len(plain)-padLen], append([]byte(nil), packet[:28]...), nil
}

// InitiatorSignedOctets builds the initiator's signed octets:
// SA_INIT request | responder nonce | prf(SK_pi, IDi body).
// idiBody is the IDi body from idBody in auth.go.
func InitiatorSignedOctets(initRequest, responderNonce []byte, s Suite, skpi, idiBody []byte) ([]byte, error) {
	idHash, err := PRF(s, skpi, idiBody)
	if err != nil {
		return nil, err
	}
	signed := make([]byte, 0, len(initRequest)+len(responderNonce)+len(idHash))
	signed = append(signed, initRequest...)
	signed = append(signed, responderNonce...)
	signed = append(signed, idHash...)
	return signed, nil
}

// ResponderSignedOctets builds the responder's signed octets:
// SA_INIT response | initiator nonce | prf(SK_pr, IDr body).
func ResponderSignedOctets(initResponse, initiatorNonce []byte, s Suite, skpr, idrBody []byte) ([]byte, error) {
	idHash, err := PRF(s, skpr, idrBody)
	if err != nil {
		return nil, err
	}
	signed := make([]byte, 0, len(initResponse)+len(initiatorNonce)+len(idHash))
	signed = append(signed, initResponse...)
	signed = append(signed, initiatorNonce...)
	signed = append(signed, idHash...)
	return signed, nil
}

// AuthMIC computes the shared-key MIC over signed octets:
// prf(prf(key, "Key Pad for IKEv2"), signed). For EAP-AKA AUTH,
// key is the MSK; for plain shared-key AUTH it is the shared
// secret.
func AuthMIC(key, signed []byte, s Suite) ([]byte, error) {
	padded, err := PRF(s, key, []byte(KeyPadForIKEv2))
	if err != nil {
		return nil, err
	}
	return PRF(s, padded, signed)
}

// BuildEAPInitiatorAuth returns the full AUTH payload (method 2,
// shared-key MIC) for IKE_AUTH(3), built from the MSK, the
// SA_INIT request, the responder nonce, SK_pi, and the IDi body.
func BuildEAPInitiatorAuth(msk, initRequest, responderNonce []byte, s Suite, skpi, idiBody []byte) ([]byte, error) {
	signed, err := InitiatorSignedOctets(initRequest, responderNonce, s, skpi, idiBody)
	if err != nil {
		return nil, err
	}
	mic, err := AuthMIC(msk, signed, s)
	if err != nil {
		return nil, err
	}
	return BuildAuthFinal(byte(AuthMethodSharedKeyMIC), mic), nil
}

// VerifyAuthMIC checks an AUTH MIC in constant time. authData
// is the MIC bytes only (the AUTH payload body after its 4-byte
// method/reserved header).
func VerifyAuthMIC(key, signed []byte, s Suite, authData []byte) error {
	expected, err := AuthMIC(key, signed, s)
	if err != nil {
		return err
	}
	if len(authData) != len(expected) || subtle.ConstantTimeCompare(authData, expected) != 1 {
		return errors.New("ike: AUTH MIC mismatch")
	}
	return nil
}
