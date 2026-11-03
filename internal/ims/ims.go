// Package ims is an IMS SIP REGISTER skeleton, not a SIP stack.
//
// It reuses VoCat upstream concepts (internal/vowifi/ims, read as
// reference only) in a small, self-contained form:
//
//   - IMPI / IMPU derivation: IMPI is IMSI@ims-domain, where the IMS
//     domain is ims.mncXXX.mccYYY.3gppnetwork.org with the MNC padded
//     to 3 digits (VoCat deriveIdentities pads a 2-digit MNC with a
//     leading zero). IMPU is sip:IMSI@ims-domain, plus a tel: form
//     when an MSISDN is known.
//   - AKA challenge: a 401 WWW-Authenticate Digest header with
//     algorithm=AKAv1-MD5 whose nonce is base64(RAND || AUTN), the
//     first 32 nonce octets (VoCat digest.go decodeAKANonce /
//     authenticateAKA). RAND is nonce[0:16], AUTN is nonce[16:32].
//   - AKAv1-MD5 response (VoCat digest.go digestResponse, 3GPP
//     TS 33.203): HA1 = MD5(username ":" realm ":" RES), where RES
//     is the raw USIM response bytes, not a password; HA2 =
//     MD5(method ":" uri); response = MD5(HA1 ":" nonce ":" nc ":"
//     cnonce ":" qop ":" HA2) when qop=auth is offered.
//   - CK/IK: the USIM also returns 16-byte CK and IK. They are NOT
//     hashed into the Digest response. In VoCat they seed the IPsec
//     security association (security.go); here they are carried in
//     AKAResult so the future IPsec step can use them, and the
//     Authorization header marks integrity-protected=no because no
//     IPsec SA exists yet in this skeleton.
//
// Transport: NONE. There is no UDP, TCP, or any socket in this
// package. The client takes a Handler function
// (func(request string) string) and the mock server is just a
// Handler (MockServer.Handle). That is deliberate: this container
// blocks UDP even on loopback, so a loopback SIP exchange cannot be
// tested here. The in-memory exchange proves the exact REGISTER /
// 401 / REGISTER / 200 sequence; wiring it to a real UDP/TCP
// P-CSCF transport is a separate, later step, as is the real USIM
// AUTHENTICATE (replacing MockSIM) and the MDD Asterisk ims_aka
// bridge concept, which is reference only and not implemented here.
package ims

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Identity is the IMS identity derived from a SIM identity.
type Identity struct {
	IMSI      string // digits only, never logged in full by callers
	MCC       string // 3 digits
	MNC       string // as supplied, 2 or 3 digits
	IMSDomain string // ims.mncXXX.mccYYY.3gppnetwork.org
	IMPI      string // IMSI@IMSDomain
	SIPIMPU   string // sip:IMSI@IMSDomain
	// TelIMPU is tel:+MSISDN when MSISDN is known. Without an MSISDN
	// (not yet read from ISIM/EF_MSISDN) it falls back to tel:IMSI
	// as a skeleton placeholder; it must not be treated as a real
	// subscriber number until MSISDN is supplied.
	TelIMPU string
	MSISDN  string
}

// DeriveIdentity builds IMPI/IMPU from IMSI + MCC/MNC, following
// VoCat: the MNC is padded to 3 digits for the IMS domain.
// It does not guess the MNC length beyond that padding rule.
func DeriveIdentity(imsi, mcc, mnc, msisdn string) (Identity, error) {
	imsi = strings.TrimSpace(imsi)
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	msisdn = strings.TrimSpace(msisdn)
	if !allDigits(imsi) || len(imsi) < 5 || len(imsi) > 16 {
		return Identity{}, fmt.Errorf("ims: IMSI is unavailable or invalid")
	}
	if !allDigits(mcc) || len(mcc) != 3 {
		return Identity{}, fmt.Errorf("ims: MCC must be 3 digits")
	}
	if !allDigits(mnc) || len(mnc) < 2 || len(mnc) > 3 {
		return Identity{}, fmt.Errorf("ims: MNC must be 2 or 3 digits")
	}
	mnc3 := mnc
	for len(mnc3) < 3 {
		mnc3 = "0" + mnc3
	}
	domain := fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc3, mcc)
	tel := ""
	if msisdn != "" {
		if !allDigits(strings.TrimPrefix(msisdn, "+")) {
			return Identity{}, fmt.Errorf("ims: MSISDN must be digits")
		}
		tel = "tel:+" + strings.TrimPrefix(msisdn, "+")
	} else {
		tel = "tel:" + imsi
	}
	return Identity{
		IMSI: imsi, MCC: mcc, MNC: mnc, IMSDomain: domain,
		IMPI:    imsi + "@" + domain,
		SIPIMPU: "sip:" + imsi + "@" + domain,
		TelIMPU: tel, MSISDN: msisdn,
	}, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// RegisterOptions controls one REGISTER build. CallID, FromTag and
// Branch are generated randomly when empty; tests set them explicitly
// so output is deterministic.
type RegisterOptions struct {
	Identity      Identity
	CallID        string
	FromTag       string
	Branch        string
	CSeq          uint32
	Expires       int
	ViaHost       string // e.g. "192.0.2.1:5060"; defaults to "127.0.0.1:5060" in text only, no socket is opened
	Contact       string // defaults to sip:IMSI@ViaHost
	Authorization string // empty => no Authorization header (first REGISTER)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// BuildRegister renders a SIP REGISTER request as text (CRLF).
// It never sends anything.
func BuildRegister(o RegisterOptions) (string, error) {
	if o.Identity.IMPI == "" || o.Identity.SIPIMPU == "" || o.Identity.IMSDomain == "" {
		return "", fmt.Errorf("ims: identity is empty (derive it with DeriveIdentity first)")
	}
	if strings.ContainsAny(o.Identity.IMPI+o.Identity.SIPIMPU+o.Identity.IMSDomain, "\r\n") {
		return "", fmt.Errorf("ims: identity contains a line break")
	}
	callID := o.CallID
	if callID == "" {
		v, err := randomHex(16)
		if err != nil {
			return "", err
		}
		callID = v
	}
	tag := o.FromTag
	if tag == "" {
		v, err := randomHex(8)
		if err != nil {
			return "", err
		}
		tag = v
	}
	branch := o.Branch
	if branch == "" {
		v, err := randomHex(12)
		if err != nil {
			return "", err
		}
		branch = v
	}
	if o.CSeq == 0 {
		o.CSeq = 1
	}
	expires := o.Expires
	if expires == 0 {
		expires = 3600
	}
	via := o.ViaHost
	if via == "" {
		via = "127.0.0.1:5060"
	}
	contact := o.Contact
	if contact == "" {
		contact = "sip:" + o.Identity.IMSI + "@" + via
	}
	lines := []string{
		"REGISTER sip:" + o.Identity.IMSDomain + " SIP/2.0",
		"Via: SIP/2.0/UDP " + via + ";branch=z9hG4bK" + branch + ";rport",
		"Max-Forwards: 70",
		"From: <" + o.Identity.SIPIMPU + ">;tag=" + tag,
		"To: <" + o.Identity.SIPIMPU + ">",
		"Call-ID: " + callID,
		fmt.Sprintf("CSeq: %d REGISTER", o.CSeq),
		"Contact: <" + contact + ">;expires=" + strconv.Itoa(expires),
		fmt.Sprintf("Expires: %d", expires),
		"Supported: path, gruu",
		"Allow: REGISTER, INVITE, ACK, CANCEL, BYE, OPTIONS, MESSAGE, SUBSCRIBE, NOTIFY",
		"User-Agent: vohiver/1",
	}
	if o.Authorization != "" {
		lines = append(lines, "Authorization: "+o.Authorization)
	}
	lines = append(lines, "", "")
	return strings.Join(lines, "\r\n"), nil
}

// Challenge is a parsed 401 WWW-Authenticate Digest AKA challenge.
type Challenge struct {
	Realm     string
	Nonce     string // base64(RAND || AUTN || server data)
	Opaque    string
	Algorithm string // must be AKAv1-MD5
	QOP       string // "auth" when offered
	RAND      []byte // nonce[0:16]
	AUTN      []byte // nonce[16:32]
}

// ParseChallenge parses one WWW-Authenticate header value (with or
// without a leading "WWW-Authenticate:" label). It requires
// algorithm=AKAv1-MD5 and a nonce of at least 32 decoded octets,
// following VoCat parseDigestChallenge / decodeAKANonce.
func ParseChallenge(value string) (Challenge, error) {
	value = strings.TrimSpace(value)
	if i := strings.Index(value, ":"); i >= 0 && strings.EqualFold(strings.TrimSpace(value[:i]), "WWW-Authenticate") {
		value = strings.TrimSpace(value[i+1:])
	}
	scheme, params, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Digest") {
		return Challenge{}, fmt.Errorf("ims: unsupported SIP authentication scheme %q", scheme)
	}
	directives, err := parseDirectives(params)
	if err != nil {
		return Challenge{}, err
	}
	ch := Challenge{
		Realm: directives["realm"], Nonce: directives["nonce"],
		Opaque: directives["opaque"], Algorithm: directives["algorithm"],
	}
	if ch.Realm == "" || ch.Nonce == "" {
		return Challenge{}, fmt.Errorf("ims: incomplete SIP digest challenge")
	}
	if ch.Algorithm == "" {
		return Challenge{}, fmt.Errorf("ims: digest challenge omitted the AKA algorithm")
	}
	if !strings.EqualFold(ch.Algorithm, "AKAv1-MD5") {
		return Challenge{}, fmt.Errorf("ims: unsupported digest algorithm %q", ch.Algorithm)
	}
	if qop := directives["qop"]; qop != "" {
		for _, c := range strings.Split(qop, ",") {
			if strings.EqualFold(strings.TrimSpace(c), "auth") {
				ch.QOP = "auth"
				break
			}
		}
		if ch.QOP == "" {
			return Challenge{}, fmt.Errorf("ims: digest challenge does not offer qop=auth")
		}
	}
	decoded, err := decodeNonce(ch.Nonce)
	if err != nil {
		return Challenge{}, err
	}
	ch.RAND = append([]byte(nil), decoded[:16]...)
	ch.AUTN = append([]byte(nil), decoded[16:32]...)
	return ch, nil
}

func decodeNonce(value string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(strings.TrimSpace(value)); err == nil && len(decoded) >= 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("ims: invalid AKA nonce")
}

// parseDirectives parses comma-separated k=v / k="v" directives,
// handling quoted values and backslash escapes like VoCat.
func parseDirectives(value string) (map[string]string, error) {
	out := map[string]string{}
	i := 0
	for i < len(value) {
		for i < len(value) && (value[i] == ' ' || value[i] == '\t' || value[i] == ',') {
			i++
		}
		if i >= len(value) {
			break
		}
		start := i
		for i < len(value) && value[i] != '=' && value[i] != ',' {
			i++
		}
		if i >= len(value) || value[i] != '=' {
			return nil, fmt.Errorf("ims: malformed digest directive")
		}
		key := strings.ToLower(strings.TrimSpace(value[start:i]))
		i++
		for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
			i++
		}
		var v strings.Builder
		if i < len(value) && value[i] == '"' {
			i++
			closed := false
			for i < len(value) {
				switch value[i] {
				case '\\':
					i++
					if i >= len(value) {
						return nil, fmt.Errorf("ims: malformed quoted digest directive")
					}
					v.WriteByte(value[i])
					i++
				case '"':
					i++
					closed = true
				default:
					v.WriteByte(value[i])
					i++
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, fmt.Errorf("ims: unterminated quoted digest directive")
			}
		} else {
			s := i
			for i < len(value) && value[i] != ',' {
				i++
			}
			v.WriteString(strings.TrimSpace(value[s:i]))
		}
		if key == "" {
			return nil, fmt.Errorf("ims: empty digest directive name")
		}
		out[key] = v.String()
	}
	return out, nil
}

// AKAResult is what a USIM returns for one RAND/AUTN challenge.
// In production this comes from a real AUTHENTICATE APDU; here
// MockSIM supplies fixed values for the in-memory test.
type AKAResult struct {
	RES []byte // 4..16 bytes
	CK  []byte // 16 bytes, for the future IPsec SA, not for Digest
	IK  []byte // 16 bytes, for the future IPsec SA, not for Digest
}

// AKAProvider is the minimal SIM side of IMS-AKA.
type AKAProvider interface {
	Authenticate(rand, autn []byte) (AKAResult, error)
}

// MockSIM is a deterministic AKAProvider for tests and the mock
// demo. It checks RAND/AUTN are 16 bytes each and returns its
// configured RES/CK/IK unchanged.
type MockSIM struct {
	RES []byte
	CK  []byte
	IK  []byte
}

func (m *MockSIM) Authenticate(randBytes, autn []byte) (AKAResult, error) {
	if len(randBytes) != 16 || len(autn) != 16 {
		return AKAResult{}, fmt.Errorf("ims: MockSIM challenge must be 16-byte RAND and 16-byte AUTN")
	}
	if len(m.RES) == 0 {
		return AKAResult{}, fmt.Errorf("ims: MockSIM RES is empty")
	}
	return AKAResult{
		RES: append([]byte(nil), m.RES...),
		CK:  append([]byte(nil), m.CK...),
		IK:  append([]byte(nil), m.IK...),
	}, nil
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ComputeDigestResponse is VoCat digestResponse: HA1 hashes the raw
// RES bytes as the password equivalent, HA2 hashes method:uri.
func ComputeDigestResponse(username, realm string, res []byte, method, uri, nonce, nc, cnonce, qop string) string {
	h1 := md5.New()
	_, _ = h1.Write([]byte(username + ":" + realm + ":"))
	_, _ = h1.Write(res)
	ha1 := hex.EncodeToString(h1.Sum(nil))
	ha2 := md5Hex(method + ":" + uri)
	if qop == "" {
		return md5Hex(ha1 + ":" + nonce + ":" + ha2)
	}
	return md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

// BuildAuthorization renders the Digest Authorization header value
// for a protected REGISTER. nc is formatted as 8 hex digits;
// integrity-protected=no records that no IPsec SA exists yet.
func BuildAuthorization(ch Challenge, username, uri string, res []byte, cnonce string, nc uint32) string {
	ncStr := fmt.Sprintf("%08x", nc)
	resp := ComputeDigestResponse(username, ch.Realm, res, "REGISTER", uri, ch.Nonce, ncStr, cnonce, ch.QOP)
	parts := []string{
		`username="` + username + `"`,
		`realm="` + ch.Realm + `"`,
		`nonce="` + ch.Nonce + `"`,
		`uri="` + uri + `"`,
		`response="` + resp + `"`,
		"algorithm=AKAv1-MD5",
	}
	if ch.Opaque != "" {
		parts = append(parts, `opaque="`+ch.Opaque+`"`)
	}
	if ch.QOP != "" {
		parts = append(parts, "qop="+ch.QOP, "nc="+ncStr, `cnonce="`+cnonce+`"`)
	}
	parts = append(parts, "integrity-protected=no")
	return "Digest " + strings.Join(parts, ", ")
}

// Response is a parsed SIP response (status line + headers only;
// body is not needed for REGISTER).
type Response struct {
	StatusCode      int
	Reason          string
	WWWAuthenticate string
	Raw             string
}

// ParseResponse parses "SIP/2.0 <code> <reason>" plus headers.
// Header names are matched case-insensitively.
func ParseResponse(raw string) (*Response, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("ims: empty SIP response")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "SIP/2.0") {
		return nil, fmt.Errorf("ims: invalid SIP response start line %q", lines[0])
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("ims: invalid SIP status code %q", fields[1])
	}
	resp := &Response{StatusCode: code, Reason: strings.Join(fields[2:], " "), Raw: raw}
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "WWW-Authenticate") {
			resp.WWWAuthenticate = strings.TrimSpace(value)
		}
	}
	return resp, nil
}

// parseRequestHeaders extracts headers (lower-cased names) and the
// method from a SIP request text, for the mock server.
func parseRequestHeaders(raw string) (method string, headers map[string]string) {
	headers = map[string]string{}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	if len(lines) > 0 {
		method = strings.Fields(lines[0])[0]
	}
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}
	return method, headers
}

// Handler is the in-memory transport: it takes a REGISTER text and
// returns a SIP response text. No socket is involved. A real
// transport would implement the same signature over UDP/TCP.
type Handler func(request string) string

// MockServer answers REGISTERs in memory: no Authorization ->
// 401 with an AKA challenge; a correct Authorization -> 200 OK;
// a present but wrong Authorization -> 403. The expected Digest
// response is recomputed from ExpectedRES with the same formula
// the client uses, so a mismatch proves a wrong RES, not a
// formatting difference.
type MockServer struct {
	Realm        string
	RAND         []byte
	AUTN         []byte
	ExpectedRES  []byte // RES the mock expects (the MockSIM's RES)
	ExpectedIMPI string
	Domain       string
	Seen         []string // request texts received, in order
}

// NewMockServer builds a mock with nonce = base64(RAND || AUTN).
func NewMockServer(realm string, randBytes, autn, expectedRES []byte, expectedIMPI, domain string) *MockServer {
	return &MockServer{
		Realm: realm, RAND: append([]byte(nil), randBytes...),
		AUTN:         append([]byte(nil), autn...),
		ExpectedRES:  append([]byte(nil), expectedRES...),
		ExpectedIMPI: expectedIMPI, Domain: domain,
	}
}

// Nonce is base64(RAND || AUTN).
func (m *MockServer) Nonce() string {
	joined := append(append([]byte(nil), m.RAND...), m.AUTN...)
	return base64.StdEncoding.EncodeToString(joined)
}

func (m *MockServer) challenge401(callID string) string {
	return "SIP/2.0 401 Unauthorized\r\n" +
		`WWW-Authenticate: Digest realm="` + m.Realm + `", nonce="` + m.Nonce() + `", algorithm=AKAv1-MD5, qop="auth"` + "\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"Content-Length: 0\r\n\r\n"
}

// Handle implements Handler.
func (m *MockServer) Handle(req string) string {
	m.Seen = append(m.Seen, req)
	method, headers := parseRequestHeaders(req)
	callID := headers["call-id"]
	if method != "REGISTER" {
		return "SIP/2.0 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
	}
	auth, ok := headers["authorization"]
	if !ok || strings.TrimSpace(auth) == "" {
		return m.challenge401(callID)
	}
	directives, err := parseDirectives(strings.TrimSpace(strings.TrimPrefix(auth, "Digest")))
	if err != nil {
		return "SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
	}
	// Recompute the expected response from the mock's RES and the
	// client's own nc/cnonce/qop, exactly as BuildAuthorization does.
	want := ComputeDigestResponse(
		directives["username"], directives["realm"], m.ExpectedRES,
		"REGISTER", directives["uri"], directives["nonce"],
		directives["nc"], directives["cnonce"], directives["qop"])
	if directives["username"] != m.ExpectedIMPI || directives["nonce"] != m.Nonce() || directives["response"] != want {
		return "SIP/2.0 403 Forbidden\r\nCall-ID: " + callID + "\r\nContent-Length: 0\r\n\r\n"
	}
	return "SIP/2.0 200 OK\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"P-Associated-URI: <sip:" + m.ExpectedIMPI + ">\r\n" +
		"Contact: " + headers["contact"] + "\r\n" +
		"Expires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"
}

// Client performs the two-step REGISTER exchange over a Handler.
type Client struct {
	Identity Identity
	SIM      AKAProvider
	CallID   string // empty => generated once per client
	FromTag  string
	Branch   string // empty => generated per REGISTER
	CNonce   string // empty => generated for the protected REGISTER
	CSeq     uint32 // 0 => starts at 1
	Expires  int
	ViaHost  string
}

// Result is a completed in-memory registration.
type Result struct {
	StatusCode    int
	FirstRequest  string
	SecondRequest string
	Challenge     Challenge
	AKA           AKAResult
	Authorization string
}

// Register runs: REGISTER (no auth) -> 401 -> AKA -> REGISTER
// (Authorization) -> 200. It returns an error for any other sequence.
func (c *Client) Register(handle Handler) (*Result, error) {
	if c.SIM == nil {
		return nil, fmt.Errorf("ims: SIM provider is required")
	}
	if handle == nil {
		return nil, fmt.Errorf("ims: handler is required")
	}
	if c.CallID == "" {
		v, err := randomHex(16)
		if err != nil {
			return nil, err
		}
		c.CallID = v
	}
	if c.FromTag == "" {
		v, err := randomHex(8)
		if err != nil {
			return nil, err
		}
		c.FromTag = v
	}
	cseq := c.CSeq
	if cseq == 0 {
		cseq = 1
	}
	first, err := BuildRegister(RegisterOptions{
		Identity: c.Identity, CallID: c.CallID, FromTag: c.FromTag,
		Branch: c.Branch, CSeq: cseq, Expires: c.Expires, ViaHost: c.ViaHost,
	})
	if err != nil {
		return nil, err
	}
	resp, err := ParseResponse(handle(first))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 200 {
		return &Result{StatusCode: 200, FirstRequest: first}, nil
	}
	if resp.StatusCode != 401 {
		return nil, fmt.Errorf("ims: first REGISTER got %d, want 401 or 200", resp.StatusCode)
	}
	if resp.WWWAuthenticate == "" {
		return nil, fmt.Errorf("ims: 401 omitted WWW-Authenticate")
	}
	ch, err := ParseChallenge(resp.WWWAuthenticate)
	if err != nil {
		return nil, err
	}
	aka, err := c.SIM.Authenticate(ch.RAND, ch.AUTN)
	if err != nil {
		return nil, fmt.Errorf("ims: SIM AKA failed: %w", err)
	}
	cnonce := c.CNonce
	if cnonce == "" {
		v, err := randomHex(16)
		if err != nil {
			return nil, err
		}
		cnonce = v
	}
	uri := "sip:" + c.Identity.IMSDomain
	auth := BuildAuthorization(ch, c.Identity.IMPI, uri, aka.RES, cnonce, 1)
	second, err := BuildRegister(RegisterOptions{
		Identity: c.Identity, CallID: c.CallID, FromTag: c.FromTag,
		Branch: c.Branch, CSeq: cseq + 1, Expires: c.Expires,
		ViaHost: c.ViaHost, Authorization: auth,
	})
	if err != nil {
		return nil, err
	}
	resp2, err := ParseResponse(handle(second))
	if err != nil {
		return nil, err
	}
	if resp2.StatusCode != 200 {
		return nil, fmt.Errorf("ims: protected REGISTER got %d, want 200", resp2.StatusCode)
	}
	return &Result{
		StatusCode: 200, FirstRequest: first, SecondRequest: second,
		Challenge: ch, AKA: aka, Authorization: auth,
	}, nil
}
