package sim

import "testing"

func TestDecodeICCID(t *testing.T) {
	raw := []byte{0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0x65, 0x87, 0xF9}
	got, err := DecodeICCID(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1234567890123456789" {
		t.Fatalf("iccid = %s", got)
	}
}

func TestDecodeIMSI(t *testing.T) {
	ef := []byte{0x08, 0x39, 0x01, 0x62, 0x10, 0x32, 0x54, 0x76, 0x98}
	got, err := DecodeIMSI(ef)
	if err != nil {
		t.Fatal(err)
	}
	if got != "310260123456789" {
		t.Fatalf("imsi = %s", got)
	}
}
