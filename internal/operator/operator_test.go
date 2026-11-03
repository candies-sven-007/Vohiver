package operator

import (
	"strings"
	"testing"
)

func TestGlobeCandidatesThreeDigitFirst(t *testing.T) {
	cands, err := CandidatesFor("515", "02")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 {
		t.Fatalf("Globe candidates = %d, want 2", len(cands))
	}
	if cands[0].MNC != "002" || cands[0].PLMN != "515002" ||
		cands[0].EPDGHostname != "epdg.epc.mnc002.mcc515.pub.3gppnetwork.org" {
		t.Fatalf("first Globe candidate wrong: %+v", cands[0])
	}
	if cands[1].MNC != "02" || cands[1].PLMN != "51502" ||
		cands[1].EPDGHostname != "epdg.epc.mnc02.mcc515.pub.3gppnetwork.org" {
		t.Fatalf("second Globe candidate wrong: %+v", cands[1])
	}
	for _, c := range cands {
		if c.EPDGHostname == "" {
			t.Fatalf("Globe ePDG must never be empty: %+v", c)
		}
	}
}

func TestGlobeDoesNotRelyOnVoCatEmptyEPDGField(t *testing.T) {
	// VoCat carrier_profiles.json entry ipcc-globe-51502 has an IKE
	// proposal and an IMS setting but NO ePDG hostname. This test
	// encodes the contract that must hold regardless of that file:
	// Globe candidates are derived from the 3GPP hostname rule,
	// never read from a profile field that is empty for Globe.
	// The proof is in the function itself: GlobeCandidates builds
	// both hostnames from the rule, and this test fails if either
	// hostname is empty or does not match the rule.
	for _, c := range GlobeCandidates() {
		want := "epdg.epc.mnc" + c.MNC + ".mcc515.pub.3gppnetwork.org"
		if c.EPDGHostname != want {
			t.Fatalf("Globe ePDG %q != rule-derived %q", c.EPDGHostname, want)
		}
		if strings.Contains(c.EPDGHostname, "mnc.mcc") {
			t.Fatalf("Globe ePDG has an empty MNC slot: %q", c.EPDGHostname)
		}
	}
	if !IsGlobe("515", "02") || !IsGlobe("515", "002") || IsGlobe("515", "03") {
		t.Fatalf("IsGlobe misclassifies a PLMN")
	}
}

func TestGlobeIKEProposalsLegacyThenModern(t *testing.T) {
	props := GlobeIKEProposals()
	if len(props) != 2 {
		t.Fatalf("Globe IKE proposals = %d, want 2", len(props))
	}
	legacy, modern := props[0], props[1]
	if legacy.Name != "legacy-sha1-modp1024" || legacy.FirstPRF != 2 ||
		legacy.FirstInteg != 2 || legacy.DHGroup != 2 || legacy.EncrKeyLen != 128 {
		t.Fatalf("legacy proposal wrong: %+v", legacy)
	}
	if modern.Name != "modern" || modern.FirstPRF != 5 || modern.FirstInteg != 12 {
		t.Fatalf("modern proposal wrong: %+v", modern)
	}
}

func TestCountriesGenericNoUKDefault(t *testing.T) {
	want := map[string]string{
		"525": "Singapore", "502": "Malaysia", "515": "Philippines",
		"452": "Vietnam", "310": "United States", "311": "United States",
		"234": "United Kingdom", "262": "Germany", "454": "Hong Kong",
	}
	if len(Countries) != len(want) {
		t.Fatalf("Countries = %d entries, want %d", len(Countries), len(want))
	}
	for mcc, name := range want {
		c, ok := ExitForMCC(mcc)
		if !ok || c.Name != name {
			t.Fatalf("ExitForMCC(%s) = %+v, %v, want %s", mcc, c, ok, name)
		}
	}
	if _, ok := ExitForMCC("999"); ok {
		t.Fatalf("unknown MCC must not fall back to any exit, let alone UK")
	}
	if _, ok := ExitForMCC(""); ok {
		t.Fatalf("empty MCC must not return an exit")
	}
}

func TestGenericCandidatesUnchangedForNonGlobe(t *testing.T) {
	cands, err := CandidatesFor("234", "33")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 || cands[0].MNC != "33" || cands[1].MNC != "033" {
		t.Fatalf("non-Globe candidates changed: %+v", cands)
	}
}
