package ike

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
)

// All tests in this file are non-UDP and use fixed inputs where
// a known answer exists, so they run in this container.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixedKeysInputs() (shared, ni, nr []byte, spiI, spiR [8]byte) {
	shared = make([]byte, 128)
	shared[127] = 64 // DH shared for priv 2 x priv 3, see TestMODP1024KnownAnswer.
	ni = bytes.Repeat([]byte{0x01}, 32)
	nr = bytes.Repeat([]byte{0x02}, 32)
	copy(spiI[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	copy(spiR[:], []byte{9, 10, 11, 12, 13, 14, 15, 16})
	return shared, ni, nr, spiI, spiR
}

func TestPRFKnownAnswerSHA1(t *testing.T) {
	// RFC 2202 test case 2: HMAC-SHA1, key "Jefe".
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	got, err := PRF(s, []byte("Jefe"), []byte("what do ya want for nothing?"))
	if err != nil {
		t.Fatal(err)
	}
	want := "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
	if hex.EncodeToString(got) != want || len(got) != 20 {
		t.Fatalf("PRF-SHA1 = %x (len %d), want %s (20)", got, len(got), want)
	}
}

func TestPRFKnownAnswerSHA256(t *testing.T) {
	// RFC 4231 test case 2: HMAC-SHA256, key "Jefe".
	s := Suite{PRFID: PRFHMACSHA256, IntegrityID: IntegrityHMACSHA256_128, EncryptionBits: 256}
	got, err := PRF(s, []byte("Jefe"), []byte("what do ya want for nothing?"))
	if err != nil {
		t.Fatal(err)
	}
	want := "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	if hex.EncodeToString(got) != want || len(got) != 32 {
		t.Fatalf("PRF-SHA256 = %x (len %d), want %s (32)", got, len(got), want)
	}
}

func TestPRFPlusPrefixAndLength(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	key := []byte("prf-plus-key")
	seed := []byte("seed-bytes")
	stream, err := PRFPlus(s, key, seed, 45)
	if err != nil {
		t.Fatal(err)
	}
	if len(stream) != 45 {
		t.Fatalf("PRF+ len = %d, want 45", len(stream))
	}
	first, err := PRF(s, key, append(append([]byte(nil), seed...), 0x01))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream[:20], first) {
		t.Fatal("PRF+ first block is not prf(key, seed|0x01)")
	}
	if _, err := PRFPlus(s, key, seed, -1); err == nil {
		t.Fatal("negative PRF+ length accepted")
	}
}

func TestMODP1024KnownAnswer(t *testing.T) {
	// priv 2 -> public 4, priv 3 -> public 8, shared 2^(2*3) = 64.
	pubA, err := MODP1024Public([]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	pubB, err := MODP1024Public([]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	if len(pubA) != 128 || pubA[127] != 4 || pubB[127] != 8 {
		t.Fatalf("public values wrong: A last=%d B last=%d len=%d", pubA[127], pubB[127], len(pubA))
	}
	sharedAB, err := MODP1024Shared([]byte{2}, pubB)
	if err != nil {
		t.Fatal(err)
	}
	sharedBA, err := MODP1024Shared([]byte{3}, pubA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedAB, sharedBA) {
		t.Fatal("DH shared secrets do not agree both ways")
	}
	if len(sharedAB) != 128 || sharedAB[127] != 64 {
		t.Fatalf("shared = last %d len %d, want 64/128", sharedAB[127], len(sharedAB))
	}
	for i := 0; i < 127; i++ {
		if sharedAB[i] != 0 {
			t.Fatalf("shared has nonzero byte at %d", i)
		}
	}
}

func TestDHExchangeAgreementDeterministic(t *testing.T) {
	a, err := NewDHExchange(bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDHExchange(bytes.NewReader(bytes.Repeat([]byte{0x22}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Public) != 128 || len(b.Public) != 128 {
		t.Fatalf("public lengths %d/%d, want 128/128", len(a.Public), len(b.Public))
	}
	sa, err := a.Shared(b.Public)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Shared(a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if len(sa) != 128 || !bytes.Equal(sa, sb) {
		t.Fatal("DH exchanges do not agree on a 128-byte shared secret")
	}
}

func TestDHRejectsBadPeerValues(t *testing.T) {
	p, err := modp1024PrimeInt()
	if err != nil {
		t.Fatal(err)
	}
	peerP := p.FillBytes(make([]byte, 128))
	one := append(make([]byte, 127), 1)
	bad := [][]byte{
		make([]byte, 127), // wrong length
		make([]byte, 128), // zero
		one,               // 1
		peerP,             // p itself
	}
	for _, v := range bad {
		if _, err := MODP1024Shared([]byte{2}, v); err == nil {
			t.Fatalf("peer value accepted, first bytes %x", v[:4])
		}
	}
	if _, err := MODP1024Public(nil); err == nil {
		t.Fatal("empty private value accepted")
	}
	if _, err := MODP1024Public([]byte{1}); err == nil {
		t.Fatal("private value 1 accepted")
	}
}

func TestDeriveKeysLengths(t *testing.T) {
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	type lens struct{ prf, integ, enc int }
	cases := []struct {
		suite Suite
		want  lens
	}{
		{Suite{PRFHMACSHA1, IntegrityHMACSHA1_96, 128}, lens{20, 20, 16}},
		{Suite{PRFHMACSHA256, IntegrityHMACSHA256_128, 256}, lens{32, 32, 32}},
		{Suite{PRFHMACSHA256, IntegrityHMACSHA256_128, 128}, lens{32, 32, 16}},
	}
	for _, c := range cases {
		keys, err := DeriveKeys(c.suite, shared, ni, nr, spiI, spiR)
		if err != nil {
			t.Fatal(err)
		}
		// Field names are exactly as in crypto.go: SKd, SKai, SKar,
		// SKei, SKer, SKpi, SKpr.
		if len(keys.SKEYSEED) != c.want.prf || len(keys.SKd) != c.want.prf ||
			len(keys.SKai) != c.want.integ || len(keys.SKar) != c.want.integ ||
			len(keys.SKei) != c.want.enc || len(keys.SKer) != c.want.enc ||
			len(keys.SKpi) != c.want.prf || len(keys.SKpr) != c.want.prf {
			t.Fatalf("suite %+v: lengths SKEYSEED=%d SKd=%d SKai=%d SKar=%d SKei=%d SKer=%d SKpi=%d SKpr=%d, want prf=%d integ=%d enc=%d",
				c.suite, len(keys.SKEYSEED), len(keys.SKd), len(keys.SKai), len(keys.SKar),
				len(keys.SKei), len(keys.SKer), len(keys.SKpi), len(keys.SKpr),
				c.want.prf, c.want.integ, c.want.enc)
		}
	}
}

func TestDeriveKeysSKEYSEEDMatchesPRF(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	keys, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	nonceKey := append(append([]byte(nil), ni...), nr...)
	want, err := PRF(s, nonceKey, shared)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.SKEYSEED, want) {
		t.Fatalf("SKEYSEED = %x, want prf(Ni|Nr, shared) = %x", keys.SKEYSEED, want)
	}
}

func TestDeriveKeysNonceSensitivityAndDeterminism(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	base, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base.SKd, again.SKd) || !bytes.Equal(base.SKpi, again.SKpi) {
		t.Fatal("same inputs gave different keys")
	}
	ni2 := append([]byte(nil), ni...)
	ni2[len(ni2)-1] ^= 0x01
	changedNi, err := DeriveKeys(s, shared, ni2, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.SKd, changedNi.SKd) {
		t.Fatal("changing Ni did not change SKd")
	}
	nr2 := append([]byte(nil), nr...)
	nr2[0] ^= 0x01
	changedNr, err := DeriveKeys(s, shared, ni, nr2, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.SKd, changedNr.SKd) {
		t.Fatal("changing Nr did not change SKd")
	}
	spiI2 := spiI
	spiI2[0] ^= 0x01
	changedSPI, err := DeriveKeys(s, shared, ni, nr, spiI2, spiR)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base.SKd, changedSPI.SKd) {
		t.Fatal("changing SPIi did not change SKd")
	}
}

func TestDeriveKeysRejectsBadSuiteAndEmptyInputs(t *testing.T) {
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	badSuites := []Suite{
		{PRFID: 99, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128},
		{PRFID: PRFHMACSHA1, IntegrityID: 99, EncryptionBits: 128},
		{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 192},
	}
	for _, s := range badSuites {
		if _, err := DeriveKeys(s, shared, ni, nr, spiI, spiR); err == nil {
			t.Fatalf("suite %+v accepted", s)
		}
	}
	good := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	if _, err := DeriveKeys(good, nil, ni, nr, spiI, spiR); err == nil {
		t.Fatal("empty shared secret accepted")
	}
	if _, err := DeriveKeys(good, shared, nil, nr, spiI, spiR); err == nil {
		t.Fatal("empty Ni accepted")
	}
}

func TestAESCBCKnownAnswerAndRoundTrip(t *testing.T) {
	// NIST SP 800-38A AES-128-CBC vector: first ciphertext block
	// is independent of the PKCS#7 padding block that follows.
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	plain := mustHex(t, "6bc1bee22e409f96e93d7e117393172a")
	ct, err := EncryptCBC(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 32 {
		t.Fatalf("PKCS#7 ciphertext len = %d, want 32 (16 data + 16 pad block)", len(ct))
	}
	if hex.EncodeToString(ct[:16]) != "7649abac8119b246cee98e9b12e9197d" {
		t.Fatalf("first CBC block = %x, want NIST vector 7649abac8119b246cee98e9b12e9197d", ct[:16])
	}
	back, err := DecryptCBC(key, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("CBC round-trip = %x, want %x", back, plain)
	}
	for _, p := range [][]byte{[]byte(""), []byte("x"), bytes.Repeat([]byte("a"), 15), bytes.Repeat([]byte("b"), 17), bytes.Repeat([]byte("c"), 100)} {
		c, err := EncryptCBC(key, iv, p)
		if err != nil {
			t.Fatal(err)
		}
		d, err := DecryptCBC(key, iv, c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(d, p) {
			t.Fatalf("CBC round-trip failed for len %d", len(p))
		}
	}
}

func TestAESCBCPKCS7TamperRejected(t *testing.T) {
	key := bytes.Repeat([]byte{0x2b}, 16)
	iv := bytes.Repeat([]byte{0x00}, 16)
	ct, err := EncryptCBC(key, iv, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	// Last byte is the pad length (11 for a 5-byte message);
	// corrupting a pad byte must fail strict PKCS#7 validation.
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-2] ^= 0x01
	if _, err := DecryptCBC(key, iv, tampered); err == nil {
		t.Fatal("tampered PKCS#7 padding accepted")
	}
	if _, err := DecryptCBC(key, iv, ct[:len(ct)-1]); err == nil {
		t.Fatal("non-block-aligned ciphertext accepted")
	}
	if _, err := EncryptCBC([]byte{1, 2, 3}, iv, []byte("x")); err == nil {
		t.Fatal("short AES key accepted")
	}
}

func skTestHeader(spiI, spiR [8]byte) []byte {
	hdr := make([]byte, 28)
	copy(hdr[0:8], spiI[:])
	copy(hdr[8:16], spiR[:])
	hdr[17] = 0x20
	hdr[18] = 35
	hdr[19] = 0x08
	binary.BigEndian.PutUint32(hdr[20:24], 1)
	return hdr
}

func TestSKPacketRoundTripSHA1(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	keys, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	nai, err := PermanentNAI("123456789012345", "234", "33")
	if err != nil {
		t.Fatal(err)
	}
	inner := BuildAuth1(nai, "ims")
	ivReader := bytes.NewReader(bytes.Repeat([]byte{0xa5}, 16))
	pkt, err := EncryptSKPacket(skTestHeader(spiI, spiR), byte(PayloadIDi), inner, s, keys.SKei, keys.SKai, ivReader)
	if err != nil {
		t.Fatal(err)
	}
	if int(pkt[16]) != PayloadSK {
		t.Fatalf("packet next = %d, want SK %d", pkt[16], PayloadSK)
	}
	if binary.BigEndian.Uint32(pkt[24:28]) != uint32(len(pkt)) {
		t.Fatal("packet length field does not match packet length")
	}
	first, plain, hdr, err := DecryptSKPacket(pkt, s, keys.SKei, keys.SKai)
	if err != nil {
		t.Fatal(err)
	}
	if first != byte(PayloadIDi) {
		t.Fatalf("first payload = %d, want %d", first, PayloadIDi)
	}
	if !bytes.Equal(plain, inner) {
		t.Fatal("SK round-trip plaintext differs from AUTH(1) chain")
	}
	if !bytes.Equal(hdr[0:8], spiI[:]) || !bytes.Equal(hdr[8:16], spiR[:]) {
		t.Fatal("SK round-trip header SPIs changed")
	}
	// Responder direction uses the peer keys and must also work.
	pktR, err := EncryptSKPacket(skTestHeader(spiI, spiR), byte(PayloadIDi), inner, s, keys.SKer, keys.SKar, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if _, plainR, _, err := DecryptSKPacket(pktR, s, keys.SKer, keys.SKar); err != nil || !bytes.Equal(plainR, inner) {
		t.Fatalf("responder SK round-trip failed: err %v", err)
	}
}

func TestSKPacketTamperRejected(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	keys, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := EncryptSKPacket(skTestHeader(spiI, spiR), byte(PayloadIDi), []byte("auth-chain-bytes"), s, keys.SKei, keys.SKai, bytes.NewReader(bytes.Repeat([]byte{0xa5}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	flipChecksum := append([]byte(nil), pkt...)
	flipChecksum[len(flipChecksum)-1] ^= 0x01
	if _, _, _, err := DecryptSKPacket(flipChecksum, s, keys.SKei, keys.SKai); err == nil {
		t.Fatal("SK packet with flipped checksum accepted")
	}
	flipCipher := append([]byte(nil), pkt...)
	flipCipher[28+4+16+2] ^= 0x01 // inside ciphertext, past IV
	if _, _, _, err := DecryptSKPacket(flipCipher, s, keys.SKei, keys.SKai); err == nil {
		t.Fatal("SK packet with flipped ciphertext accepted")
	}
	if _, _, _, err := DecryptSKPacket(pkt, s, keys.SKer, keys.SKar); err == nil {
		t.Fatal("SK packet decrypted with the wrong direction keys")
	}
}

func TestSKPacketRoundTripSHA256(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA256, IntegrityID: IntegrityHMACSHA256_128, EncryptionBits: 256}
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	keys, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	inner := []byte("hello SK world") // 14 bytes -> 16-byte ciphertext
	pkt, err := EncryptSKPacket(skTestHeader(spiI, spiR), byte(PayloadEAP), inner, s, keys.SKei, keys.SKai, bytes.NewReader(bytes.Repeat([]byte{0x33}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	// 28 header + 4 SK header + 16 IV + 16 ciphertext + 16 checksum.
	if len(pkt) != 80 {
		t.Fatalf("SHA256 SK packet len = %d, want 80", len(pkt))
	}
	first, plain, _, err := DecryptSKPacket(pkt, s, keys.SKei, keys.SKai)
	if err != nil {
		t.Fatal(err)
	}
	if first != byte(PayloadEAP) || !bytes.Equal(plain, inner) {
		t.Fatalf("SHA256 SK round-trip failed: first=%d plain=%q", first, plain)
	}
}

func TestIntegrityMACLengthsAndSensitivity(t *testing.T) {
	sha1Suite := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	sha256Suite := Suite{PRFID: PRFHMACSHA256, IntegrityID: IntegrityHMACSHA256_128, EncryptionBits: 256}
	data := []byte("packet-without-checksum")
	m1, err := IntegrityMAC(sha1Suite, bytes.Repeat([]byte{0x01}, 20), data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m1) != 12 {
		t.Fatalf("SHA1-96 MAC len = %d, want 12", len(m1))
	}
	m2, err := IntegrityMAC(sha256Suite, bytes.Repeat([]byte{0x01}, 32), data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m2) != 16 {
		t.Fatalf("SHA256-128 MAC len = %d, want 16", len(m2))
	}
	m3, err := IntegrityMAC(sha1Suite, bytes.Repeat([]byte{0x02}, 20), data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m1, m3) {
		t.Fatal("integrity MAC did not change with the key")
	}
}

func TestAuthMICChangesWithID(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	keys, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	msk := bytes.Repeat([]byte{0x09}, 64)
	initReq := []byte("fake-sa-init-request-packet")
	respNonce := bytes.Repeat([]byte{0x07}, 16)
	nai1, _ := PermanentNAI("123456789012345", "234", "33")
	nai2, _ := PermanentNAI("123456789012346", "234", "33")
	idi1 := idBody(3, nai1)
	idi2 := idBody(3, nai2)
	signed1, err := InitiatorSignedOctets(initReq, respNonce, s, keys.SKpi, idi1)
	if err != nil {
		t.Fatal(err)
	}
	signed2, err := InitiatorSignedOctets(initReq, respNonce, s, keys.SKpi, idi2)
	if err != nil {
		t.Fatal(err)
	}
	mic1, err := AuthMIC(msk, signed1, s)
	if err != nil {
		t.Fatal(err)
	}
	mic2, err := AuthMIC(msk, signed2, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(mic1) != 20 {
		t.Fatalf("AUTH MIC len = %d, want PRF length 20", len(mic1))
	}
	if bytes.Equal(mic1, mic2) {
		t.Fatal("AUTH MIC did not change when the IDi identity changed")
	}
	// Same ID, different responder nonce -> different MIC.
	signedNonce2, err := InitiatorSignedOctets(initReq, bytes.Repeat([]byte{0x08}, 16), s, keys.SKpi, idi1)
	if err != nil {
		t.Fatal(err)
	}
	micNonce2, err := AuthMIC(msk, signedNonce2, s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mic1, micNonce2) {
		t.Fatal("AUTH MIC did not change when the responder nonce changed")
	}
	// Same signed octets, different MSK -> different MIC.
	micMsk2, err := AuthMIC(bytes.Repeat([]byte{0x08}, 64), signed1, s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mic1, micMsk2) {
		t.Fatal("AUTH MIC did not change when the MSK changed")
	}
	if err := VerifyAuthMIC(msk, signed1, s, mic1); err != nil {
		t.Fatalf("correct AUTH MIC rejected: %v", err)
	}
	bad := append([]byte(nil), mic1...)
	bad[0] ^= 0x01
	if err := VerifyAuthMIC(msk, signed1, s, bad); err == nil {
		t.Fatal("tampered AUTH MIC accepted")
	}
}

func TestBuildEAPInitiatorAuthPayload(t *testing.T) {
	s := Suite{PRFID: PRFHMACSHA1, IntegrityID: IntegrityHMACSHA1_96, EncryptionBits: 128}
	shared, ni, nr, spiI, spiR := fixedKeysInputs()
	keys, err := DeriveKeys(s, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	msk := bytes.Repeat([]byte{0x09}, 64)
	nai, _ := PermanentNAI("123456789012345", "234", "33")
	payload, err := BuildEAPInitiatorAuth(msk, []byte("fake-sa-init-request"), bytes.Repeat([]byte{0x07}, 16), s, keys.SKpi, idBody(3, nai))
	if err != nil {
		t.Fatal(err)
	}
	// Generic header (4) + AUTH body: method byte + 3 reserved + 20-byte MIC.
	if len(payload) != 28 {
		t.Fatalf("AUTH payload len = %d, want 28", len(payload))
	}
	if payload[4] != byte(AuthMethodSharedKeyMIC) {
		t.Fatalf("AUTH method = %d, want %d", payload[4], AuthMethodSharedKeyMIC)
	}
	types, err := ParseAuthChainWithFirst(PayloadAuth, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 1 || types[0] != PayloadAuth {
		t.Fatalf("AUTH chain = %v, want [%d]", types, PayloadAuth)
	}
	// Responder side: signed octets + MIC verify round-trip.
	idr := idBody(2, "ims")
	signedR, err := ResponderSignedOctets([]byte("fake-sa-init-response"), ni, s, keys.SKpr, idr)
	if err != nil {
		t.Fatal(err)
	}
	micR, err := AuthMIC(msk, signedR, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthMIC(msk, signedR, s, micR); err != nil {
		t.Fatalf("responder AUTH MIC rejected: %v", err)
	}
}

func TestPinnedSuiteMatchesPinnedSA(t *testing.T) {
	encrID, prfID, integID, _, keyLen := PinnedSA()
	if encrID != EncryptionAESCBC {
		t.Fatalf("PinnedSA encr = %d, want %d", encrID, EncryptionAESCBC)
	}
	s := PinnedSuite()
	if s.PRFID != prfID || s.IntegrityID != integID || s.EncryptionBits != keyLen {
		t.Fatalf("PinnedSuite = %+v, want PRF %d integ %d bits %d", s, prfID, integID, keyLen)
	}
}

var _ = big.NewInt
