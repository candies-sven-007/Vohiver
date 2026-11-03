// Command ike-decode decodes one IKEv2 packet from hex, for
// one-time UDP capture analysis on a host where UDP is allowed.
// It never touches the network itself, so it also runs here.
//
// Usage:
//   ike-decode <hex>           # packet as one hex string
//   echo <hex> | ike-decode   # or from stdin
//   ike-decode -file capture.hex
//
// Example workflow on the UK VPS: capture with tcpdump, copy one
// SA_INIT request or response as hex, feed it here, and read the
// field-by-field output instead of guessing from "timeout".
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/candies-sven-007/vohiver/internal/ike"
)

func main() {
	file := flag.String("file", "", "file containing one hex packet")
	flag.Parse()
	var raw string
	switch {
	case *file != "":
		b, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		raw = string(b)
	case flag.NArg() > 0:
		raw = flag.Arg(0)
	default:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		raw = string(b)
	}
	raw = strings.Join(strings.Fields(raw), "")
	pkt, err := hex.DecodeString(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hex decode:", err)
		os.Exit(1)
	}
	dec, err := ike.Decode(pkt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(dec.String())
	cookie, has, err := ike.ExtractCookie(dec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if has {
		fmt.Printf("cookie: len=%d hex=%s\n", len(cookie), hex.EncodeToString(cookie))
	}
}
