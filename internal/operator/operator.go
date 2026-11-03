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
	mcc = strings.TrimSpace(mcc)
	mnc2 = strings.TrimSpace(mnc2)
	if mcc == "" || mnc2 == "" {
		return nil, fmt.Errorf("operator: MCC or MNC candidate is empty (identity not ready)")
	}
	var out []Candidate
	for _, mnc := range MNCForms(mnc2) {
		out = append(out, Candidate{
			MCC:          mcc,
			MNC:          mnc,
			PLMN:         mcc + mnc,
			EPDGHostname: fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", mnc, mcc),
			IMSDomain:    fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc),
		})
	}
	return out, nil
}
