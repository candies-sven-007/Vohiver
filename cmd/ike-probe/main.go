// Command ike-probe sends one IKEv2 IKE_SA_INIT through a SOCKS5
// egress and prints the response. See internal/ike for the packet.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/candies-sven-007/vohiver/internal/ike"
)

func main() {
	proxy := flag.String("proxy", "", "SOCKS5 proxy URL, e.g. socks5://127.0.0.1:1080 (empty = direct)")
	target := flag.String("target", "", "ePDG IPv4 address")
	port := flag.Int("port", 500, "ePDG UDP port")
	flag.Parse()
	if *target == "" {
		fmt.Fprintln(os.Stderr, "ike-probe: -target is required")
		os.Exit(2)
	}
	r := ike.ProbeSAInit(*proxy, *target, *port)
	fmt.Printf("%+v\n", r)
	if !r.OK {
		os.Exit(1)
	}
}
