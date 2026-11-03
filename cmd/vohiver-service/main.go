// Command vohiver-service is the Vohiver v2 first service.
//
// It is NOT yet a VoWiFi IMS service: calls, SMS and ePDG/IKEv2 are
// out of this version's scope. What it does, using exactly the
// probe-validated path (v1.3: MF/ICCID/DIR/IMSI with P2=04 + Le=00,
// ADF.USIM with P2=04 case 3, ISD-R with Lc=0x10), is:
//
//   - read SIM identity (masked ICCID/IMSI, MCC, MNC candidate)
//     from a physical SIM and from a physical eSIM's default profile
//   - probe ISD-R to prove (or not prove) an eUICC
//   - serve that result over HTTP, so a WebUI can replace the old
//     VoHive binary's broken LPA/eUICC path without touching it
//
// Usage on the stick (separate directory, never alongside the old
// VoHive binary, never with the md VoWiFi engine running):
//
//	LD_LIBRARY_PATH=/opt/mdd/current/lib ./vohiver-service -reader Alcor -port 7576
//	curl http://127.0.0.1:7576/api/identity
//	curl http://127.0.0.1:7576/api/euicc
//	curl http://127.0.0.1:7576/health
//
// Output safety: ICCID/IMSI are returned MASKED only (first 4 + last 4).
// ATR hex is card-type data, not subscriber data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/candies-sven-007/vohiver/internal/operator"
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

// readIdentity mirrors cmd/pcsc-probe v1.3 exactly.
func readIdentity(c *pcsc.Client) (sim.Identity, error) {
	var id sim.Identity
	tx := func(apdu []byte) ([]byte, uint16, error) { return c.Transmit(apdu) }

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

	fcp, sw, err := tx(mustAPDU("00A40004022F0000"))
	if err != nil || sw != 0x9000 || len(fcp) < 8 {
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
	aid, _ := sim.FindUSIMAID(records)
	if aid == "" {
		return id, nil
	}
	id.USIMAID = aid
	aidBytes, _ := hexAPDU(aid)
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

type identityResponse struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	Reader      string `json:"reader,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	ATR         string `json:"atr,omitempty"`
	ICCIDMasked string `json:"iccid_masked,omitempty"`
	IMSImasked  string `json:"imsi_masked,omitempty"`
	MCC         string `json:"mcc,omitempty"`
	MNC2        string `json:"mnc2_candidate,omitempty"`
	USIMAID     string `json:"usim_aid,omitempty"`
	ISDRSW      string `json:"isd_r_select_sw,omitempty"`
	IsEUICC     bool   `json:"is_euicc_proven"`
	Env         string `json:"env"`
}

func readOnce(readerSub string) identityResponse {
	resp := identityResponse{Env: pcsc.EnvReport()}
	ctx, readers, ret, err := pcsc.Establish()
	if err != nil {
		resp.Error = fmt.Sprintf("EstablishContext ret=0x%08X err=%v", ret, err)
		return resp
	}
	reader, err := pcsc.PickReader(readers, readerSub)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	client, err := pcsc.Connect(ctx, reader)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	defer client.Close()
	atr, proto, err := client.Status()
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	resp.Reader = reader
	resp.Protocol = proto
	resp.ATR = atr
	id, err := readIdentity(client)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	resp.ICCIDMasked = sim.Mask(id.ICCID)
	resp.IMSImasked = sim.Mask(id.IMSI)
	resp.MCC = id.MCC()
	resp.MNC2 = id.MNC2()
	resp.USIMAID = id.USIMAID
	_, sw, _ := client.Transmit(mustAPDU("00A4040010A0000005591010FFFFFFFF890000010000"))
	resp.ISDRSW = fmt.Sprintf("0x%04X", sw)
	resp.IsEUICC = sw == 0x9000
	resp.OK = true
	return resp
}

func main() {
	readerSub := flag.String("reader", "Alcor", "reader name substring, empty = first reader")
	port := flag.Int("port", 7576, "HTTP port (7576 by default, so it does not clash with the old VoHive 7575)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "vohiver-service v2"})
	})
	mux.HandleFunc("/api/identity", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(readOnce(*readerSub))
	})
	mux.HandleFunc("/api/euicc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := readOnce(*readerSub)
		json.NewEncoder(w).Encode(map[string]any{
			"ok": resp.OK, "error": resp.Error, "reader": resp.Reader,
			"is_euicc_proven": resp.IsEUICC, "isd_r_select_sw": resp.ISDRSW,
		})
	})
	mux.HandleFunc("/api/operator", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := readOnce(*readerSub)
		if !resp.OK {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": resp.Error})
			return
		}
		cands, err := operator.Candidates(resp.MCC, resp.MNC2)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "mcc": resp.MCC, "mnc2_candidate": resp.MNC2,
			"note": "MNC length is unknown; try candidates in order, do not guess",
			"candidates": cands,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "vohiver-service v2: /health, /api/identity, /api/euicc, /api/operator")
		fmt.Fprintln(w, "VoWiFi IMS registration, calls and SMS are NOT in this version.")
	})
	addr := fmt.Sprintf(":%d", *port)
	fmt.Printf("vohiver-service v2 listening on %s (reader=%q)\n", addr, *readerSub)
	fmt.Println("env:", pcsc.EnvReport())
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
}
