// Package ike, decode.go: a pure packet decoder. It never touches
// UDP, so it runs in this container. It is the tool for the
// one-time UDP capture analysis on a host where UDP is allowed:
// feed it a captured SA_INIT request or response (hex) and it
// prints header, payload chain, SA proposals/transforms, KE,
// nonce and Notify (including COOKIE) field by field, instead of
// guessing from "timeout".
package ike

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Payload type numbers (RFC 7296 §3.2).
const (
	PayloadSA     = 33
	PayloadKE     = 34
	PayloadNi     = 40
	PayloadNotify = 41
)

// Notify message types (RFC 7296 §3.10.1, as used by VoCat).
const (
	NotifyNoProposal   = 14
	NotifyInitialContact = 16384
	NotifyCookie       = 16390
)

func payloadName(t int) string {
	switch t {
	case PayloadSA:
		return "SA"
	case PayloadKE:
		return "KE"
	case PayloadNi:
		return "Ni"
	case PayloadNotify:
		return "Notify"
	case 0:
		return "NONE"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

func notifyName(t uint16) string {
	switch t {
	case NotifyNoProposal:
		return "NO_PROPOSAL_CHOSEN"
	case NotifyInitialContact:
		return "INITIAL_CONTACT"
	case NotifyCookie:
		return "COOKIE"
	case 17:
		return "INVALID_KE_PAYLOAD"
	default:
		return fmt.Sprintf("notify-%d", t)
	}
}

// Header is an IKEv2 message header.
type Header struct {
	InitiatorSPI string
	ResponderSPI string
	NextPayload  int
	Version      byte
	Exchange     int
	Flags        byte
	MessageID    uint32
	Length       uint32
}

// Payload is one generic payload, plus parsed fields where known.
type Payload struct {
	Type       int
	Name       string
	Length     int
	Body       []byte // after the 4-byte generic header
	// SA, when Type == PayloadSA.
	Proposals []Proposal
	// KE, when Type == PayloadKE.
	DHGroup int
	// Notify, when Type == PayloadNotify.
	NotifyType uint16
	NotifyName string
	NotifyData []byte
}

// Proposal is one SA proposal with its transforms.
type Proposal struct {
	Number     int
	ProtocolID int
	SPISize    int
	Transforms []Transform
}

// Transform is one SA transform.
type Transform struct {
	Type     int
	ID       int
	KeyLen   int // ENCR key length, -1 when absent
	HasKeyLen bool
}

// DecodedPacket is a fully parsed IKEv2 message.
type DecodedPacket struct {
	Header   Header
	Payloads []Payload
}

// String prints the packet field by field, for capture analysis.
func (d *DecodedPacket) String() string {
	var b strings.Builder
	h := d.Header
	fmt.Fprintf(&b, "header: initiator_spi=%s responder_spi=%s next=%s version=0x%02x exchange=%d flags=0x%02x message_id=%d length=%d\n",
		h.InitiatorSPI, h.ResponderSPI, payloadName(h.NextPayload), h.Version, h.Exchange, h.Flags, h.MessageID, h.Length)
	for _, p := range d.Payloads {
		fmt.Fprintf(&b, "payload: %s len=%d\n", p.Name, p.Length)
		for _, pr := range p.Proposals {
			fmt.Fprintf(&b, "  proposal num=%d protocol=%d spi_size=%d transforms=%d\n", pr.Number, pr.ProtocolID, pr.SPISize, len(pr.Transforms))
			for _, tr := range pr.Transforms {
				if tr.HasKeyLen {
					fmt.Fprintf(&b, "    transform type=%d id=%d keylen=%d\n", tr.Type, tr.ID, tr.KeyLen)
				} else {
					fmt.Fprintf(&b, "    transform type=%d id=%d\n", tr.Type, tr.ID)
				}
			}
		}
		if p.Type == PayloadKE {
			fmt.Fprintf(&b, "  ke: dh_group=%d ke_data_len=%d\n", p.DHGroup, len(p.Body)-4)
		}
		if p.Type == PayloadNi {
			fmt.Fprintf(&b, "  nonce_len=%d\n", len(p.Body))
		}
		if p.Type == PayloadNotify {
			fmt.Fprintf(&b, "  notify: type=%d (%s) data_len=%d data_hex=%s\n", p.NotifyType, p.NotifyName, len(p.NotifyData), hex.EncodeToString(p.NotifyData))
		}
	}
	return b.String()
}

// Decode parses an IKEv2 packet without any network I/O.
func Decode(pkt []byte) (*DecodedPacket, error) {
	if len(pkt) < 28 {
		return nil, fmt.Errorf("ike: packet too short: %d bytes", len(pkt))
	}
	hdrLen := binary.BigEndian.Uint32(pkt[24:28])
	if int(hdrLen) != len(pkt) {
		return nil, fmt.Errorf("ike: header length %d does not match packet length %d", hdrLen, len(pkt))
	}
	d := &DecodedPacket{Header: Header{
		InitiatorSPI: hex.EncodeToString(pkt[0:8]),
		ResponderSPI: hex.EncodeToString(pkt[8:16]),
		NextPayload:  int(pkt[16]),
		Version:      pkt[17],
		Exchange:     int(pkt[18]),
		Flags:        pkt[19],
		MessageID:    binary.BigEndian.Uint32(pkt[20:24]),
		Length:       hdrLen,
	}}
	next := int(pkt[16])
	off := 28
	for next != 0 {
		if off+4 > len(pkt) {
			return nil, fmt.Errorf("ike: truncated payload header at offset %d", off)
		}
		plen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if plen < 4 || off+plen > len(pkt) {
			return nil, fmt.Errorf("ike: bad payload length %d at offset %d", plen, off)
		}
		body := pkt[off+4 : off+plen]
		p := Payload{Type: next, Name: payloadName(next), Length: plen, Body: append([]byte(nil), body...)}
		switch next {
		case PayloadSA:
			props, err := parseProposals(body)
			if err != nil {
				return nil, err
			}
			p.Proposals = props
		case PayloadKE:
			if len(body) < 4 {
				return nil, fmt.Errorf("ike: truncated KE payload")
			}
			p.DHGroup = int(binary.BigEndian.Uint16(body[0:2]))
		case PayloadNotify:
			if len(body) < 4 {
				return nil, fmt.Errorf("ike: truncated Notify payload")
			}
			spiSize := int(body[1])
			if 4+spiSize > len(body) {
				return nil, fmt.Errorf("ike: truncated Notify SPI")
			}
			p.NotifyType = binary.BigEndian.Uint16(body[2:4])
			p.NotifyName = notifyName(p.NotifyType)
			p.NotifyData = append([]byte(nil), body[4+spiSize:]...)
		}
		d.Payloads = append(d.Payloads, p)
		next = int(pkt[off])
		off += plen
	}
	return d, nil
}

func parseProposals(body []byte) ([]Proposal, error) {
	var out []Proposal
	off := 0
	for off < len(body) {
		if off+8 > len(body) {
			return nil, fmt.Errorf("ike: truncated proposal at offset %d", off)
		}
		plen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		if plen < 8 || off+plen > len(body) {
			return nil, fmt.Errorf("ike: bad proposal length %d at offset %d", plen, off)
		}
		pr := Proposal{Number: int(body[off+4]), ProtocolID: int(body[off+5]), SPISize: int(body[off+6])}
		numTransforms := int(body[off+7])
		toff := off + 8 + pr.SPISize
		for i := 0; i < numTransforms; i++ {
			if toff+8 > off+plen {
				return nil, fmt.Errorf("ike: truncated transform %d", i)
			}
			tlen := int(binary.BigEndian.Uint16(body[toff+2 : toff+4]))
			if tlen < 8 || toff+tlen > off+plen {
				return nil, fmt.Errorf("ike: bad transform length %d", tlen)
			}
			tr := Transform{Type: int(body[toff+4]), ID: int(binary.BigEndian.Uint16(body[toff+6 : toff+8])), KeyLen: -1}
			// ENCR key-length attribute: TV form, 0x800E, value.
			ab := body[toff+8 : toff+tlen]
			if len(ab) >= 4 && ab[0] == 0x80 && ab[1] == 0x0e {
				tr.KeyLen = int(binary.BigEndian.Uint16(ab[2:4]))
				tr.HasKeyLen = true
			}
			pr.Transforms = append(pr.Transforms, tr)
			toff += tlen
		}
		out = append(out, pr)
		off += plen
	}
	return out, nil
}

// ExtractCookie returns the COOKIE notify data from a decoded
// packet, and whether exactly one such notify was present.
// An empty or duplicated cookie is an error, matching VoCat's
// ikeInitCookie behaviour: do not resend a guess.
func ExtractCookie(d *DecodedPacket) ([]byte, bool, error) {
	var found []byte
	count := 0
	for _, p := range d.Payloads {
		if p.Type == PayloadNotify && p.NotifyType == NotifyCookie {
			count++
			found = p.NotifyData
		}
	}
	if count == 0 {
		return nil, false, nil
	}
	if count > 1 {
		return nil, false, fmt.Errorf("ike: multiple COOKIE notifications")
	}
	if len(found) == 0 {
		return nil, false, fmt.Errorf("ike: empty COOKIE notification")
	}
	return found, true, nil
}

// HasSA reports whether the packet carries an SA payload.
func (d *DecodedPacket) HasSA() bool {
	for _, p := range d.Payloads {
		if p.Type == PayloadSA {
			return true
		}
	}
	return false
}
