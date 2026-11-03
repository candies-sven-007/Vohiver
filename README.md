# Vohiver v1 — PCSC reader probe for the 410 stick

## Goal

Fix, from first principles, the one failure that blocked VoWiFi on the
410 stick: a PCSC reader (AK9563 / Alcor Link) is listed, but no PCSC
context can be established to read the card identity, so VoWiFi
reconciliation keeps warning "SIM identity not ready" and never starts.

Vohiver v1 is **not** a VoWiFi service yet. It is a small, testable
probe that proves the reader layer, then becomes the device layer for
a later VoWiFi build. IMS registration, calls and SMS are explicitly
out of scope for v1.

## Stick constraints (do not change these)

- Hardware: UFI103S Qualcomm Snapdragon 410 (MSM8916) stick, OpenStick
  Debian 11, expansion board, USB CCID reader (Alcor Link AK9563).
- Daemon: `mdd-pcscd` is a pinned pcsc-lite daemon, server protocol
  **4:5**. It carries the patched CCID driver for this reader.
- Do NOT unmask/start the system `pcscd`, and do NOT stop
  `mdd-pcscd` to "fix" anything. Do NOT run the md VoWiFi engine
  and a probe/VoHive binary at the same time: they contend for the
  same card.
- The old VoHive binary in `~/vohive-test` on the stick is untouched
  by this repository. Test v1 in a **separate** directory.

## The protocol problem, precisely

pcsc-lite negotiates a client/server protocol version. The pinned
daemon speaks 4:5. A client library speaking 4:4 is rejected with
"Communication protocol mismatch" and surfaces as
`SCARD_E_SERVICE_STOPPED (0x8010001E)`. That code does **not** mean
the daemon stopped.

goscard (`github.com/ElMostafaIdrassi/goscard` v1.0.0, also used by
the old binary) has no `libpcsclite` link dependency because at
runtime it `purego.Dlopen`s `libpcsclite.so` / `libpcsclite.so.1`
from the normal loader search path. Therefore `LD_LIBRARY_PATH`
decides which client library it loads:

- Without the pinned lib: system libpcsclite (4:4) -> mismatch ->
  `0x8010001E`, eSIM tab and WebUI restart fail the same way.
- With `LD_LIBRARY_PATH=/opt/mdd/current/lib`: pinned lib (4:5) ->
  context succeeds, as already proven by `pcsc_scan` with that
  variable (reader listed, card inserted, ATR changes on swap).

So v1's first fix is not a new protocol implementation: it is to
make the loader choice explicit, log it on every run, and fail with
a diagnosis that names the mismatch instead of blaming the card.
A future version may vendor a pinned client or negotiate, but v1
must first prove the pinned-lib path end to end.

## Research base (all read, none copied wholesale)

- **MengMengCode/VoCat** (Go, port 7575): device model
  (`internal/device/types.go`), VoWiFi lifecycle
  (`internal/vowifi/types.go`: `idle -> sim_ready -> access_ready ->
  tunnel_ready -> ims_ready -> sms_ready`, `SIMIdentity` with
  ICCID/IMSI/HomeMCC/HomeMNC, and the rule that the SIM reader must
  supply MCC/MNC — the orchestrator never guesses MNC length or a
  phone number from IMSI). VoCat is modem-first; v1 adds the PCSC
  reader as a new identity provider for that same shape.
- **MDD slim branch** (`candies-sven-007/mdd-sim-gateway`,
  `slim-reader-vowifi`, `engine/ami_usim.py`): USIM identity via
  PCSC — EF.ICCID (MF/2FE2, 10 BCD bytes), EF.DIR scan for the USIM
  AID prefix `A0000000871002`, ADF.USIM, EF.IMSI (6F07) decoding,
  and APDU normalisation (61xx GET RESPONSE, 6Cxx Le retry, shared
  transaction). v1 ports that decoding to Go in `internal/sim`.
- **goscard v1.0.0** (`scard_nix.go`, `scard_linux.go`): context,
  ListReaders, Connect (T0|T1), Status, Transmit, GetStatusChange,
  and the dynamic libpcsclite loading described above.
- **Old binary (not source)**: module `iniwex5/vohive`, stripped
  ARM64 Go, goscard v1.0.0, `pool_pcsc` / `pool_vowifi` / eSIM
  PCSCChannel. Upstream `iniwex5/vohive` now returns 404 and the
  Hercules mirror holds only binaries/config, so the old second-dev
  source cannot be recovered or patched. Vohiver rebuilds the
  reader layer instead of patching that binary.

## Design v1

- `internal/pcsc`: Establish / ListReaders / Connect / Transmit
  (61xx + 6Cxx normalisation) / Status / GetStatusChange. Every
  failure keeps the raw goscard return code; `0x8010001E` is mapped
  to the protocol-mismatch diagnosis.
- `internal/sim`: DecodeICCID, DecodeIMSI, EF.DIR USIM-AID scan.
  Same path for a physical SIM and for a physical eSIM's default
  profile. No MNC-length guessing, no key material (no AUTHENTICATE).
- `cmd/pcsc-probe`: list readers, connect, print ATR + protocol,
  read identity, probe ISD-R selection, optional watch mode.
  - eUICC: ISD-R SELECT success proves eUICC; failure proves
    nothing by itself (some cards need a logical channel first).
    LPA / lpac profile download, enable, delete are **v2**, not v1.
  - Card swap: watch mode polls Status; on ATR change it re-reads
    identity. Hot-swap without re-reading is a known gap in the
    old binary's flow.
  - Output safety: ICCID/IMSI are masked (first 4 + last 4) in
    probe output. ATR is card-type data, not subscriber data.

## Build (GitHub Action)

`.github/workflows/build-arm64.yml` builds
`cmd/pcsc-probe` for `linux/arm64` with `CGO_ENABLED=0` and uploads
`vohiver-probe` as an artifact. Download it from the Actions run;
do not build on the stick (RAM/disk are tight).

## Test on the stick (separate directory only)

```sh
# On the stick, in its own SSH session. Keep mdd-pcscd running.
# Stop the md engine/control/orchestrator first, and do NOT run
# the old VoHive binary at the same time.
mkdir -p ~/vohiver-test2
# copy vohiver-probe (from the Action artifact) into ~/vohiver-test2

# Expected to FAIL with the diagnostic (proves the mismatch path):
./vohiver-probe -reader Alcor

# Expected to SUCCEED on this stick:
LD_LIBRARY_PATH=/opt/mdd/current/lib ./vohiver-probe -reader Alcor

# Card-swap test (swap SIM <-> eSIM while it runs):
LD_LIBRARY_PATH=/opt/mdd/current/lib ./vohiver-probe -reader Alcor -watch 60
```

Pass criteria for v1: the pinned-lib run lists the reader, connects,
prints an ATR, and prints a masked identity with MCC; swapping the
card changes the ATR and the masked identity in watch mode.
Fail criteria: any unmasked ICCID/IMSI in output, any claim that
VoWiFi/IMS/calls/SMS work (they are not in v1), or any change to
`~/vohive-test` / `mdd-pcscd` / the md engine from this repo.

## Not yet verified (explicitly out of v1)

- VoWiFi IMS registration, ePDG/IKEv2 tunnel, calls, SMS, USSD.
- LPA profile management (download/enable/disable/delete, EID).
- PIN handling, multi-reader arbitration, WebUI.
- Any stick run at all: until a user runs the Action artifact in
  `~/vohiver-test2` as above, v1 is compile-checked only.

## Licence / attribution

New code here is for the user's own learning project. Upstream
components keep their own licences: VoCat, MDD, goscard, pcsc-lite
and lpac. Do not commit real credentials, IMEI, ICCID or IMSI to
this repository.
