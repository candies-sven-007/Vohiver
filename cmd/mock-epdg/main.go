// Command mock-epdg is a one-time UDP validation server, NOT a
// container test: this container blocks UDP, so this program must
// run on a host where UDP is allowed (the UK VPS or the stick).
//
// It listens on UDP :5000, answers any IKE_SA_INIT with a fixed
// SA_INIT response (exchange 34, responder SPI, SA payload), and
// prints every packet it receives. Run it in one window, then run
// ike-probe against it in another window:
//
//	mock-epdg -port 5000
//	ike-probe -target 127.0.0.1 -port 5000
//
// A successful run proves the SA_INIT packet, the KE value and
// the UDP path end-to-end, without touching a real ePDG or a SIM.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	port := flag.Int("port", 5000, "UDP port to listen on")
	flag.Parse()
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer pc.Close()
	fmt.Printf("mock-epdg listening on UDP :%d\n", *port)
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Printf("got %d bytes from %s, exchange=%d\n", n, addr, buf[18])
		if n < 28 {
			continue
		}
		resp := make([]byte, 28)
		copy(resp[0:8], buf[0:8])
		copy(resp[8:16], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
		resp[16] = 33
		resp[17] = 0x20
		resp[18] = 34
		resp[19] = 0x20
		binary.BigEndian.PutUint32(resp[24:28], 28)
		pc.WriteTo(resp, addr)
	}
}
