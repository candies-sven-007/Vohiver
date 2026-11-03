// Command pcsc-probe is the Vohiver v1 diagnostic, not a VoWiFi service.
//
// It answers, in order, the exact questions that were unanswered on the
// stick with the old VoHive binary:
//
//  1. Can a goscard context be established at all, and with which
//     LD_LIBRARY_PATH? (4:4 client vs 4:5 pinned daemon -> 0x8010001E)
//  2. Which readers are listed, and does the chosen reader hold a card?
//  3. Can the card's USIM identity be read (ICCID + IMSI) from a
//     physical SIM and from a physical eSIM's default profile alike?
//  4. Does the card select ISD-R (eUICC evidence), or not?
//  5. Does a card swap change the ATR / identity (watch mode)?
//
// Output safety: ICCID/IMSI are printed MASKED only (first 4 + last 4).
// ATR hex is printed because it identifies the card type, not the
// subscriber. Never paste unmasked probe output into a public issue.
//
// Usage on the stick (separate directory, never alongside the old
// VoHive binary, never with the md VoWiFi engine running):
//
//	LD_LIBRARY_PATH=/opt/mdd/current/lib ./vohiver-probe -reader Alcor
//	LD_LIBRARY_PATH=/opt/mdd/current/lib ./vohiver-probe -reader Alcor -watch 30
//
// Without LD_LIBRARY_PATH the probe is expected to fail on this stick
// with 0x8010001E; that failure is itself the diagnostic.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/candies-sven-007/vohiver/internal/pcsc"
	"github.com/candies-sven-007/vohiver/internal/sim"
)

func hexAPDU(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var v int
		if _, err := fmt.Sscanf(s[i:i+2], "%02x", &v); err != nil {
			return nil, err
		}
		out = append(out, byte(v))
	}
	return out, nil
}

func mustAPDU(s string) []byte {
	b, err := hexAPDU(s)
	if err != nil {
		panic(err)
	}
	return b
}

// readIdentity implements the MDD read path: MF -> EF.ICCID, then
// EF.DIR -> USIM AID -> ADF.USIM -> EF.IMSI. A physical SIM and an
// eSTK physical eSIM use this same path for their default profile;
// the eUICC LPA path is deliberately separate (see readEUICC).
func readIdentity(c *pcsc.Client) (sim.Identity, error) {
	var id sim.Identity
	tx := func(apdu []byte) ([]byte, uint16, error) { return c.Transmit(apdu) }

	// v1.1 fix (2026-11-03 stick test): the v1 SELECT MF used P2=00, case 3,
	// and the eSTK card answered 0x6B00 (wrong P1-P2). MDD's proven path on
	// this stick uses P2=04 + Le=00 (case 4) for MF/EF selections, so use
	// MDD's exact APDUs here: 00A40004023F0000, 00A40004022FE200, etc.
	if _, sw, err := tx(mustAPDU("00A40004023F0000")); err != nil || sw != 0x9000 {
		return id, fmt.Errorf("SELECT MF: sw=0x%04X err=%v", sw, err)
	}
	if _, sw, err := tx(mustAPDU("00A40004022FE200")); err != nil || sw != 0x9000 {
		return id, fmt.Errorf("SELECT EF.ICCID: sw=0x%04X err=%v", sw, err)
	}
	raw, sw, err := tx(mustAPDU("00B000000A"))
	if err != nil || sw != 0x9000 {
		return id, fmt.Errorf("READ EF.ICCID: sw=0x%04X err=%v", sw, err)
	}
	iccid, err := sim.DecodeICCID(raw)
	if err != nil {
		return id, err
	}
	id.ICCID = iccid

	// EF.DIR scan for the USIM AID, using MDD's exact method (v1.3 fix
	// 2026-11-03): v1/v1.2 read records with Le=0xFF and relied on a
	// 6Cxx correction, but a card that answers 6700 (wrong length)
	// instead of 6Cxx then yields zero records and a silent
	// ICCID-only identity, as seen on the U Mobile physical SIM.
	// MDD takes the record length from the SELECT EF.DIR FCP
	// (byte 7) and reads each record with exactly that Le.
	fcp, sw, err := tx(mustAPDU("00A40004022F0000"))
	if err != nil || sw != 0x9000 || len(fcp) < 8 {
		// No usable EF.DIR: report ICCID-only identity, with the
		// DIR status printed so the cause is not silent.
		fmt.Printf("dir: select_sw=0x%04X fcp_len=%d (no usable EF.DIR, ICCID-only)\n", sw, len(fcp))
		return id, nil
	}
	recordLen := fcp[7]
	var records [][]byte
	for rec := 1; rec <= 10; rec++ {
		data, sw, err := tx([]byte{0x00, 0xB2, byte(rec), 0x04, recordLen})
		if err != nil || sw != 0x9000 || len(data) == 0 {
			break
		}
		records = append(records, data)
	}
	fmt.Printf("dir: record_len=%d records_read=%d\n", recordLen, len(records))
	aid, _ := sim.FindUSIMAID(records)
	if aid == "" {
		return id, nil
	}
	id.USIMAID = aid
	aidBytes, _ := hexAPDU(aid)
	// v1.2 fix (2026-11-03 stick test): v1 selected ADF.USIM with P2=00
	// + Le=00 and the eSTK card answered 0x6F00. MDD's proven path uses
	// P2=04, case 3, no Le: 00A40404<len><aid>. Use MDD's exact form here.
	selectAID := append([]byte{0x00, 0xA4, 0x04, 0x04, byte(len(aidBytes))}, aidBytes...)
	if _, sw, err := tx(selectAID); err != nil || sw != 0x9000 {
		return id, fmt.Errorf("SELECT ADF.USIM (%s): sw=0x%04X err=%v", aid, sw, err)
	}
	if _, sw, err := tx(mustAPDU("00A40004026F0700")); err != nil || sw != 0x9000 {
		return id, fmt.Errorf("SELECT EF.IMSI: sw=0x%04X err=%v", sw, err)
	}
	raw, sw, err = tx(mustAPDU("00B0000009"))
	if err != nil || sw != 0x9000 {
		return id, fmt.Errorf("READ EF.IMSI: sw=0x%04X err=%v", sw, err)
	}
	imsi, err := sim.DecodeIMSI(raw)
	if err != nil {
		return id, err
	}
	id.IMSI = imsi
	return id, nil
}

// readEUICC only probes ISD-R selection. It does NOT run an LPA
// (lpac) and does NOT download/enable/delete profiles. v2 owns LPA.
func readEUICC(c *pcsc.Client) sim.Identity {
	var id sim.Identity
	// ISD-R AID (16 bytes, v1.3 fix: v1 declared Lc=0x11/17 and the
	// card answered 6700 wrong length): A0000005591010FFFFFFFF8900000100
	_, sw, err := c.Transmit(mustAPDU("00A4040010A0000005591010FFFFFFFF890000010000"))
	id.ISDRSW = sw
	if err == nil && sw == 0x9000 {
		id.IsEUICC = true
	}
	return id
}

func main() {
	readerSub := flag.String("reader", "Alcor", "reader name substring, empty = first reader")
	watchSecs := flag.Int("watch", 0, "if >0, poll ATR for this many seconds and re-read identity on change")
	flag.Parse()

	fmt.Println("vohiver pcsc-probe v1")
	fmt.Println("env:", pcsc.EnvReport())
	fmt.Println("note: output masks ICCID/IMSI; ATR is card-type data, not subscriber data")

	ctx, readers, ret, err := pcsc.Establish()
	if err != nil {
		fmt.Printf("FAIL EstablishContext ret=0x%08X err=%v\n", ret, err)
		if ret == pcsc.SCARDEServiceStopped {
			fmt.Println("DIAGNOSIS: 0x8010001E here is the pinned-daemon protocol mismatch (client 4:4 vs server 4:5), not a stopped daemon.")
			fmt.Println("RETRY: LD_LIBRARY_PATH=/opt/mdd/current/lib ./vohiver-probe -reader Alcor")
			fmt.Println("DO NOT: unmask system pcscd, stop mdd-pcscd, or blame the card/reader for this code.")
		}
		os.Exit(2)
	}
	defer func() {
		// ctx is released by Client.Close; keep Establish symmetric.
		_ = ctx
	}()
	fmt.Printf("readers (%d):\n", len(readers))
	for _, r := range readers {
		fmt.Printf("  - %s\n", r)
	}
	reader, err := pcsc.PickReader(readers, *readerSub)
	if err != nil {
		fmt.Println("FAIL pick reader:", err)
		os.Exit(2)
	}
	fmt.Println("chosen reader:", reader)

	client, err := pcsc.Connect(ctx, reader)
	if err != nil {
		fmt.Println("FAIL connect:", err)
		os.Exit(2)
	}
	defer client.Close()

	atr, proto, err := client.Status()
	if err != nil {
		fmt.Println("FAIL status:", err)
		os.Exit(2)
	}
	fmt.Printf("card: protocol=%s atr=%s\n", proto, atr)

	id, err := readIdentity(client)
	if err != nil {
		fmt.Println("FAIL read identity:", err)
		fmt.Println("This is the 'SIM identity not ready' state the old VoWiFi reconcile loop warned about.")
		os.Exit(3)
	}
	fmt.Printf("identity: iccid_masked=%s imsi_masked=%s mcc=%s mnc2_candidate=%s (mnc length unknown) usim_aid=%s\n",
		sim.Mask(id.ICCID), sim.Mask(id.IMSI), id.MCC(), id.MNC2(), id.USIMAID)
	eu := readEUICC(client)
	fmt.Printf("euicc: isd_r_select_sw=0x%04X is_euicc_proven=%v (false = not proven, not proven-absent; LPA is v2)\n", eu.ISDRSW, eu.IsEUICC)

	if *watchSecs > 0 {
		fmt.Printf("watch: polling ATR for %ds, swap the card to test re-detection\n", *watchSecs)
		deadline := time.Now().Add(time.Duration(*watchSecs) * time.Second)
		lastATR := atr
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
			atr2, _, err := client.Status()
			if err != nil {
				fmt.Println("watch: status error (card removed?):", err)
				continue
			}
			if atr2 != lastATR {
				fmt.Printf("watch: CARD CHANGED old_atr=%s new_atr=%s\n", lastATR, atr2)
				lastATR = atr2
				id2, err := readIdentity(client)
				if err != nil {
					fmt.Println("watch: re-read failed:", err)
				} else {
					fmt.Printf("watch: new identity iccid_masked=%s imsi_masked=%s mcc=%s\n",
						sim.Mask(id2.ICCID), sim.Mask(id2.IMSI), id2.MCC())
				}
			}
		}
	}
	fmt.Println("OK: probe complete. VoWiFi IMS registration, calls and SMS are NOT in v1 scope.")
}
