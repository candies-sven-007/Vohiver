// Package operator derives VoWiFi targets generically from a SIM's
// MCC/MNC, so Vohiver is not hardcoded to one operator or country.
//
// Design (checked against VoCat upstream, 2026-11-03):
//   - VoCat matches 652 carrier profiles by home PLMN / ICCID prefix,
//     and its ePDG resolver tries both 2-digit and 3-digit MNC forms.
//   - The standard 3GPP ePDG hostname is
//     epdg.epc.mncXXX.mccYYY.pub.3gppnetwork.org
//   - The standard IMS domain is
//     ims.mncXXX.mccYYY.3gppnetwork.org
//
// This package does NOT guess the MNC length: the probe only reports
// a 2-digit MNC candidate, so EPDGHostnames returns both forms when
// they differ (e.g. mnc33 and mnc033 for MCC 234, MNC candidate 33),
// and the caller must try them in order and use the one that
// resolves and accepts IKEv2. A carrier-overrides table (by PLMN)
// can be added later for operators whose ePDG does not follow the
// standard hostname; it must never be filled by guessing.
//
// No VoWiFi tunnel, IKEv2 or IMS registration is in this package:
// that is the next step, after the ePDG hostname for the MCC 234
// card is confirmed by DNS on the stick.
package operator

import (
	"fmt"
	"strings"
)

// Candidate is one ePDG/IMS target derived from MCC/MNC.
type Candidate struct {
	MCC          string `json:"mcc"`
	MNC          string `json:"mnc"`
	PLMN         string `json:"plmn"`
	EPDGHostname string `json:"epdg_hostname"`
	IMSDomain    string `json:"ims_domain"`
}

// MNCForms returns the MNC forms to try, in order, without guessing
// which length is correct: the raw candidate first, then the
// alternate padding form (2-digit <-> 3-digit with a leading zero).
func MNCForms(mnc string) []string {
	mnc = strings.TrimSpace(mnc)
	if mnc == "" {
		return nil
	}
	forms := []string{mnc}
	if len(mnc) == 2 {
		forms = append(forms, "0"+mnc)
	} else if len(mnc) == 3 && strings.HasPrefix(mnc, "0") {
		forms = append(forms, mnc[1:])
	}
	return forms
}

// Candidates returns ePDG/IMS candidates for a MCC and a 2-digit
// MNC candidate. It returns an error when MCC or MNC is empty, so
// callers cannot silently build a target from a missing identity.
func Candidates(mcc, mnc2 string) ([]Candidate, error) {
	return CandidatesFor(mcc, mnc2)
}

// CandidatesFor is the generic entry point: Globe (51502) is
// routed to its special case, every other PLMN uses the standard
// MNC-forms order. No caller has to remember the Globe exception.
func CandidatesFor(mcc, mnc2 string) ([]Candidate, error) {
	mcc = strings.TrimSpace(mcc)
	mnc2 = strings.TrimSpace(mnc2)
	if mcc == "" || mnc2 == "" {
		return nil, fmt.Errorf("operator: MCC or MNC candidate is empty (identity not ready)")
	}
	if IsGlobe(mcc, mnc2) {
		return GlobeCandidates(), nil
	}
	var out []Candidate
	for _, mnc := range MNCForms(mnc2) {
		out = append(out, makeCandidate(mcc, mnc))
	}
	return out, nil
}

func makeCandidate(mcc, mnc string) Candidate {
	return Candidate{
		MCC:          mcc,
		MNC:          mnc,
		PLMN:         mcc + mnc,
		EPDGHostname: fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", mnc, mcc),
		IMSDomain:    fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc),
	}
}

// IsGlobe reports whether MCC/MNC (2-digit candidate, or a 3-digit
// form) is Philippines Globe, PLMN 51502 / 515002.
func IsGlobe(mcc, mnc string) bool {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	return mcc == "515" && (mnc == "02" || mnc == "002")
}

// GlobeCandidates returns Globe's ePDG/IMS candidates in the order
// to try them: Globe's custom ePDG first, then the standard forms.
//
// Globe does NOT use the standard 3GPP ePDG hostname: its real
// ePDG is weconnect.globe.com.ph (Pixel IMS / PH WiFi-Calling
// lists, checked 2026-11-06; VoCat's ipcc-globe-51502 profile also
// has no ePDG field at all). Live DoH on 2026-11-06:
// weconnect.globe.com.ph -> 124.6.181.102, while
// epdg.epc.mnc002.mcc515.pub.3gppnetwork.org is NXDOMAIN and
// epdg.epc.mnc02.mcc515.pub.3gppnetwork.org returns only 127.0.0.1.
// The custom candidate keeps the standard IMS domain; the two
// standard candidates remain as fallbacks only.
func GlobeCandidates() []Candidate {
	custom := makeCandidate("515", "002")
	custom.EPDGHostname = "weconnect.globe.com.ph"
	return []Candidate{
		custom,
		makeCandidate("515", "002"),
		makeCandidate("515", "02"),
	}
}

// IKEProposal is one IKE SA attempt, in VoCat's sense: "modern"
// and "legacy-sha1-modp1024" are not different DH groups, they are
// the same single proposal with the PRF/INTEG ordering flipped
// (VoCat internal/vowifi/ike/provider.go ikeOffer: legacyFirst
// puts SHA1 first, otherwise SHA256 first, same DH group).
// Globe is therefore tried legacy-first, then modern, keeping
// MODP1024 in both attempts; only the PRF/INTEG order changes.
type IKEProposal struct {
	Name       string `json:"name"`
	FirstPRF   int    `json:"first_prf"`
	FirstInteg int    `json:"first_integ"`
	DHGroup    int    `json:"dh_group"`
	EncrKeyLen int    `json:"encr_key_len"`
}

// LegacyProposal is the proven single proposal: ENCR AES_CBC
// id 12 key length 128, PRF HMAC_SHA1 id 2 first, INTEG
// HMAC_SHA1_96 id 2 first, DH MODP1024 id 2.
func LegacyProposal() IKEProposal {
	return IKEProposal{Name: "legacy-sha1-modp1024", FirstPRF: 2, FirstInteg: 2, DHGroup: 2, EncrKeyLen: 128}
}

// ModernProposal is VoCat's "modern" ordering: PRF HMAC_SHA256
// id 5 first, INTEG HMAC_SHA256_128 id 12 first, same MODP1024
// group. It is a second attempt, never the only attempt for Globe.
func ModernProposal() IKEProposal {
	return IKEProposal{Name: "modern", FirstPRF: 5, FirstInteg: 12, DHGroup: 2, EncrKeyLen: 128}
}

// GlobeIKEProposals returns Globe's IKE attempts in order:
// legacy first, then modern.
func GlobeIKEProposals() []IKEProposal {
	return []IKEProposal{LegacyProposal(), ModernProposal()}
}

// Country is one supported country exit, keyed by MCC. The exit
// is a label for the per-country proxy exit (MDD's egress model),
// not a hardcoded node: the caller resolves the actual node for
// that country from its own proxy library.
type Country struct {
	MCC       string `json:"mcc"`
	Name      string `json:"name"`
	ExitLabel string `json:"exit_label"`
}

// Countries is the generic multi-country list. It is keyed by MCC,
// never by a single country, and UK is just one entry in it.
var Countries = []Country{
	{MCC: "525", Name: "Singapore", ExitLabel: "SG"},
	{MCC: "502", Name: "Malaysia", ExitLabel: "MY"},
	{MCC: "515", Name: "Philippines", ExitLabel: "PH"},
	{MCC: "452", Name: "Vietnam", ExitLabel: "VN"},
	{MCC: "310", Name: "United States", ExitLabel: "US"},
	{MCC: "311", Name: "United States", ExitLabel: "US"},
	{MCC: "234", Name: "United Kingdom", ExitLabel: "GB"},
	{MCC: "262", Name: "Germany", ExitLabel: "DE"},
	{MCC: "454", Name: "Hong Kong", ExitLabel: "HK"},
}

// ExitForMCC returns the per-country exit for an MCC, or false
// when the MCC has no entry. Callers must not fall back to a UK
// exit on false; an unknown MCC is an error, not a UK default.
func ExitForMCC(mcc string) (Country, bool) {
	mcc = strings.TrimSpace(mcc)
	for _, c := range Countries {
		if c.MCC == mcc {
			return c, true
		}
	}
	return Country{}, false
}
