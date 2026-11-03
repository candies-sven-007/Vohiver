// Package sim decodes the two identity files every VoWiFi reader must be
// able to read from a physical SIM and from a physical eSIM's default
// profile, using exactly the same APDU path for both:
//
//   - EF.ICCID (MF / 2FE2): 10 BCD bytes, no PIN required.
//   - EF.IMSI  (ADF.USIM / 6F07): length byte + swapped-nibble digits.
//
// This mirrors the decoding in MDD's engine/ami_usim.py (read_iccid,
// dec_imsi, USIM_AID_PREFIX, EF.DIR scan). It deliberately does NOT guess
// the MNC length from the IMSI: VoCat's SIMIdentity has the same rule
// (HomeMCC/HomeMNC must be supplied by the SIM reader). The probe reports
// MCC and a 2-digit MNC candidate, and flags MNC length as unknown.
//
// No keying material is ever read here. AUTHENTICATE (EAP-AKA / IMS-AKA)
// is out of scope for v1; see README.md.
package sim

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Identity is the masked-safe part of a card identity. The probe prints
// MaskedICCID / MaskedIMSI only; the full values stay in memory for the
// future VoWiFi layer and must never be logged.
type Identity struct {
	ICCID string
	IMSI  string
	// USIM AID found via EF.DIR, empty when the card has no USIM ADF.
	USIMAID string
	// IsEUICC is true only when the ISD-R application selects cleanly.
	// False means "not proven eUICC", not "proven not eUICC": some cards
	// require a logical channel before ISD-R answers.
	IsEUICC bool
	// ISDRSW is the status word of the ISD-R SELECT, for diagnostics.
	ISDRSW uint16
}

func (id Identity) MCC() string {
	if len(id.IMSI) >= 3 {
		return id.IMSI[:3]
	}
	return ""
}

// MNC2 is the first two MNC digits. A 3-digit MNC, if any, must come from
// EF.AD / carrier data, never from guessing here.
func (id Identity) MNC2() string {
	if len(id.IMSI) >= 5 {
		return id.IMSI[3:5]
	}
	return ""
}

// Mask returns first 4 + "****" + last 4, or "****" for short values.
// Never print a full ICCID/IMSI in probe output.
func Mask(v string) string {
	if len(v) >= 8 {
		return v[:4] + "****" + v[len(v)-4:]
	}
	if v == "" {
		return "(empty)"
	}
	return "****"
}

func swapNibbles(b []byte) string {
	const hexd = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(hexd[c&0x0F])
		sb.WriteByte(hexd[c>>4])
	}
	return sb.String()
}

// DecodeICCID decodes exactly 10 BCD bytes, like MDD read_iccid.
func DecodeICCID(data []byte) (string, error) {
	if len(data) != 10 {
		return "", fmt.Errorf("sim: ICCID must be 10 bytes, got %d", len(data))
	}
	iccid := strings.TrimRight(swapNibbles(data), "fF")
	for _, r := range iccid {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("sim: ICCID is not all digits")
		}
	}
	if len(iccid) < 15 {
		return "", fmt.Errorf("sim: ICCID too short (%d digits)", len(iccid))
	}
	return iccid, nil
}

// DecodeIMSI decodes EF.IMSI, like MDD dec_imsi: first byte is the
// length in bytes, the first nibble of the swapped digits is parity.
func DecodeIMSI(ef []byte) (string, error) {
	if len(ef) < 2 {
		return "", fmt.Errorf("sim: EF.IMSI too short")
	}
	length := int(ef[0])
	if length < 1 || length > 8 || len(ef) < 1+length {
		return "", fmt.Errorf("sim: EF.IMSI bad length %d", length)
	}
	swapped := swapNibbles(ef[1 : 1+length])
	swapped = strings.TrimRight(swapped, "fF")
	if len(swapped) < 2 {
		return "", fmt.Errorf("sim: EF.IMSI has no digits")
	}
	imsi := swapped[1:]
	if len(imsi) < 5 || len(imsi) > 15 {
		return "", fmt.Errorf("sim: IMSI length %d out of range", len(imsi))
	}
	for _, r := range imsi {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("sim: IMSI is not all digits")
		}
	}
	return imsi, nil
}

// USIMAIDPrefix is the 3GPP USIM AID prefix (MDD: USIM_AID_PREFIX).
const USIMAIDPrefix = "A0000000871002"

// FindUSIMAID scans EF.DIR records for a USIM AID. records are the raw
// record bytes returned by READ RECORD; each record is expected to start
// with 0x61 (application template) and contain a 0x4F AID tag.
func FindUSIMAID(records [][]byte) (string, string) {
	var first string
	for _, rec := range records {
		if len(rec) < 5 || rec[0] != 0x61 {
			continue
		}
		// Minimal TLV walk: look for tag 0x4F after the template header.
		for i := 2; i+2 < len(rec); i++ {
			if rec[i] != 0x4F {
				continue
			}
			aidLen := int(rec[i+1])
			if i+2+aidLen > len(rec) {
				break
			}
			aid := strings.ToUpper(hex.EncodeToString(rec[i+2 : i+2+aidLen]))
			if first == "" {
				first = aid
			}
			if strings.HasPrefix(aid, USIMAIDPrefix) {
				return aid, aid
			}
			break
		}
	}
	return first, first
}
