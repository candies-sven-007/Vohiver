// Package pcsc is the Vohiver v1 PCSC reader layer.
//
// Why this package exists (stick constraint, read before changing it):
//
//   - The stick runs mdd-pcscd, a pinned pcsc-lite daemon whose server
//     protocol is 4:5. A client library speaking 4:4 is rejected by the
//     daemon with "Communication protocol mismatch" and the client
//     surfaces it as SCARD_E_SERVICE_STOPPED (0x8010001E). That does NOT
//     mean the daemon is down, the reader is broken, or the card is bad.
//   - goscard (ElMostafaIdrassi/goscard v1.0.0, used by the old VoHive
//     binary) does NOT link libpcsclite at build time. At runtime it
//     purego-dlopens libpcsclite.so / libpcsclite.so.1 from the normal
//     loader search path, so LD_LIBRARY_PATH decides which client
//     library it actually loads. Running the old binary without
//     LD_LIBRARY_PATH=/opt/mdd/current/lib loaded the system 4:4
//     library and failed; running pcsc_scan with that variable loaded
//     the pinned 4:5 library and succeeded. The probe therefore prints
//     LD_LIBRARY_PATH on every run and, on 0x8010001E, tells the user
//     to retry with the pinned library instead of blaming the card.
//   - Do NOT "fix" this by unmasking the system pcscd or stopping
//     mdd-pcscd: the pinned daemon carries the patched CCID driver
//     for this reader.
//
// APDU normalisation follows MDD engine/ami_usim.py::_xfr:
// 61xx -> GET RESPONSE until data is complete; 6Cxx -> retry with the
// card's Le. Callers always see (data, 0x9000) on success.
package pcsc

import (
	"fmt"
	"os"
	"strings"

	"github.com/ElMostafaIdrassi/goscard"
)

// SCARDEServiceStopped is the code the old WebUI showed for the
// protocol mismatch. Keep it as a named constant so the probe can
// distinguish "daemon protocol mismatch" from "daemon down".
const SCARDEServiceStopped uint64 = 0x8010001E

// Client wraps a goscard context + one connected card.
type Client struct {
	ctx    goscard.Context
	card   goscard.Card
	pci    goscard.SCardIORequest
	reader string
}

// EnvReport is printed on every probe run: it is the single most useful
// line for diagnosing a 4:4/4:5 mismatch.
func EnvReport() string {
	return fmt.Sprintf("LD_LIBRARY_PATH=%q (pinned mdd lib is /opt/mdd/current/lib; empty means the system libpcsclite will be loaded)",
		os.Getenv("LD_LIBRARY_PATH"))
}

// Establish creates a context and lists readers. It returns the raw
// goscard return code alongside the error so callers can test for
// SCARDEServiceStopped without string matching.
func Establish() (goscard.Context, []string, uint64, error) {
	if err := goscard.Initialize(goscard.NewDefaultFileLogger(goscard.LogLevelError, os.Stderr)); err != nil {
		return goscard.Context{}, nil, 0, fmt.Errorf("goscard initialize: %w", err)
	}
	ctx, ret, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		goscard.Finalize()
		return goscard.Context{}, nil, uint64(ret), fmt.Errorf("SCardEstablishContext ret=0x%08X: %w", uint64(ret), err)
	}
	readers, ret, err := ctx.ListReaders(nil)
	if err != nil {
		ctx.Release()
		goscard.Finalize()
		return goscard.Context{}, nil, uint64(ret), fmt.Errorf("ListReaders ret=0x%08X: %w", uint64(ret), err)
	}
	return ctx, readers, 0, nil
}

// PickReader returns the first reader whose name contains substr
// (case-insensitive, e.g. "Alcor"), or the first reader when substr is empty.
func PickReader(readers []string, substr string) (string, error) {
	if len(readers) == 0 {
		return "", fmt.Errorf("no PCSC readers found (is mdd-pcscd running?)")
	}
	if substr == "" {
		return readers[0], nil
	}
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r), strings.ToLower(substr)) {
			return r, nil
		}
	}
	return "", fmt.Errorf("no reader matching %q; readers: %v", substr, readers)
}

// Connect connects shared T0|T1 and starts a transaction.
func Connect(ctx goscard.Context, reader string) (*Client, error) {
	card, ret, err := ctx.Connect(reader, goscard.SCardShareShared, goscard.SCardProtocolT0|goscard.SCardProtocolT1)
	if err != nil {
		return nil, fmt.Errorf("Connect ret=0x%08X: %w", uint64(ret), err)
	}
	c := &Client{ctx: ctx, card: card, reader: reader}
	st, ret, err := card.Status()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("Status ret=0x%08X: %w", uint64(ret), err)
	}
	switch st.ActiveProtocol {
	case goscard.SCardProtocolT0:
		c.pci = goscard.SCardIoRequestT0
	case goscard.SCardProtocolT1:
		c.pci = goscard.SCardIoRequestT1
	default:
		c.pci = goscard.SCardIoRequestT0
	}
	if ret, err := card.BeginTransaction(); err != nil {
		c.Close()
		return nil, fmt.Errorf("BeginTransaction ret=0x%08X: %w", uint64(ret), err)
	}
	return c, nil
}

func (c *Client) Close() {
	c.card.EndTransaction(goscard.SCardLeaveCard)
	c.card.Disconnect(goscard.SCardLeaveCard)
	c.ctx.Release()
	goscard.Finalize()
}

// Status returns ATR hex and the active protocol string.
func (c *Client) Status() (atr string, proto string, err error) {
	st, ret, err := c.card.Status()
	if err != nil {
		return "", "", fmt.Errorf("Status ret=0x%08X: %w", uint64(ret), err)
	}
	return st.Atr, st.ActiveProtocol.String(), nil
}

// Transmit sends one APDU and normalises 61xx / 6Cxx, like MDD _xfr.
// goscard Transmit returns the response including SW1/SW2 as the last
// two bytes; those are split out here.
func (c *Client) Transmit(apdu []byte) (data []byte, sw uint16, err error) {
	for attempt := 0; attempt < 8; attempt++ {
		recv, ret, err := c.card.Transmit(&c.pci, apdu, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("Transmit ret=0x%08X: %w", uint64(ret), err)
		}
		if len(recv) < 2 {
			return nil, 0, fmt.Errorf("Transmit: short response %d bytes", len(recv))
		}
		data, sw = recv[:len(recv)-2], uint16(recv[len(recv)-2])<<8|uint16(recv[len(recv)-1])
		switch {
		case sw>>8 == 0x61:
			// GET RESPONSE for the remaining bytes.
			more, sw2, err := c.Transmit([]byte{0x00, 0xC0, 0x00, 0x00, byte(sw & 0xFF)})
			if err != nil {
				return nil, 0, err
			}
			data = append(data, more...)
			// If GET RESPONSE itself was not 9000, report the accepted
			// data as success only when we actually got data; otherwise
			// surface the new status word.
			if sw2 != 0x9000 && len(more) == 0 {
				return data, sw2, nil
			}
			return data, 0x9000, nil
		case sw>>8 == 0x6C:
			apdu = withLe(apdu, byte(sw&0xFF))
			continue
		default:
			return data, sw, nil
		}
	}
	return nil, 0, fmt.Errorf("Transmit: card kept re-asking (61xx/6Cxx loop)")
}

func withLe(apdu []byte, le byte) []byte {
	if len(apdu) <= 5 {
		return append(append([]byte{}, apdu[:4]...), le)
	}
	lc := int(apdu[4])
	if 5+lc > len(apdu) {
		return apdu
	}
	out := append([]byte{}, apdu[:5+lc]...)
	return append(out, le)
}

// GetStatusChangeOnce runs a zero-timeout status change check, used by
// the probe's --watch loop to detect card removal/insertion (event
// count in the upper bits changes) without blocking forever.
func (c *Client) GetStatusChangeOnce(reader string) (cur, evt string, err error) {
	states := []goscard.SCardReaderState{{Reader: reader}}
	ret, err := c.ctx.GetStatusChange(goscard.NewTimeout(0), states)
	if err != nil {
		return "", "", fmt.Errorf("GetStatusChange ret=0x%08X: %w", uint64(ret), err)
	}
	return states[0].CurrentState.String(), states[0].EventState.String(), nil
}

// Hex helpers for APDUs built by callers.
func APDU(b ...byte) []byte { return b }
