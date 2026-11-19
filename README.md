# KCQ Scooter BLE protocol — reverse engineering notes

Complete documentation of the Bluetooth Low Energy protocol used by the **KCQ Scooter**
app (`com.kcq.kcqscooter`) and the OEM scooters it ships with — the ones advertising as
`KCQScooterXX`.

Everything below was derived from a live device plus static analysis of the shipping APK.
Nothing is guesswork without being labelled as such.

> **TL;DR** — The protocol is simple, unauthenticated and now fully mapped. You *can* set
> per-gear speed limits over BLE, including values outside the range the app allows.
> But the ESC carries a **hard-coded 35 km/h ceiling** (byte `d[3]` of the `0x56` frame,
> constant `0x23`), which matches the measured physical peak of ~34 km/h. No command
> changes it. There is **no** current, acceleration, wheel-size or "sport mode" parameter
> anywhere in the firmware. More speed needs hardware.

---

## Table of contents

1. [Scope, hardware and what was tested](#1-scope-hardware-and-what-was-tested)
2. [Quick start](#2-quick-start)
3. [Device discovery and GATT map](#3-device-discovery-and-gatt-map)
4. [Frame layer](#4-frame-layer)
5. [Telemetry — notification type `0x55`](#5-telemetry--notification-type-0x55)
6. [Gear config — notification type `0x56`](#6-gear-config--notification-type-0x56)
7. [Limit ranges — notification type `0x57`](#7-limit-ranges--notification-type-0x57)
8. [Command reference](#8-command-reference)
9. [The `A5` settings-byte bit shift](#9-the-a5-settings-byte-bit-shift)
10. [How the shipping app implements it (decompiled)](#10-how-the-shipping-app-implements-it-decompiled)
11. [Experiment log](#11-experiment-log)
12. [Speed unlocking: what works, what doesn't](#12-speed-unlocking-what-works-what-doesnt)
13. [Dead ends — do not repeat these](#13-dead-ends--do-not-repeat-these)
14. [Gotchas and troubleshooting](#14-gotchas-and-troubleshooting)
15. [Tool reference](#15-tool-reference)
16. [Reproducing the APK analysis](#16-reproducing-the-apk-analysis)
17. [Hardware: if you want actual more speed](#17-hardware-if-you-want-actual-more-speed)
18. [Appendix A — raw frame captures](#appendix-a--raw-frame-captures)
19. [Appendix B — settings byte state history](#appendix-b--settings-byte-state-history)
20. [Appendix C — reference implementation](#appendix-c--reference-implementation)
21. [Appendix D — app version history](#appendix-d--app-version-history)
22. [Disclaimer](#disclaimer)
23. [License](#license)

---

## 1. Scope, hardware and what was tested

| Item | Value |
|---|---|
| Device name (advertised) | `KCQScooter03` (user-changeable via `fff3`) |
| Device class | iScooter-class OEM e-scooter, 19 mph (30.6 km/h) stock |
| App package | `com.kcq.kcqscooter` |
| App version analysed | 1.5.4 (versionCode 54, published 2026-10-15) |
| APK size / MD5 | 25,898,806 bytes / `45ca3ef20f64ecddbe295204e5da8be1` |
| Host | Linux, BlueZ, Python 3.14, bleak 1.1.1 |
| BLE adapter | generic USB HCI (`hci0`) |

**Verified facts.** Everything in sections 3–9 was observed on the wire. The
"hard-coded 35 km/h" claim in section 6.3 is a *strong inference* from a constant that
never changed plus a measured peak that matches it — it is labelled as such.

---

## 2. Quick start

```bash
python -m venv .venv
.venv/bin/pip install bleak

# dump the GATT tree and capture 15 s of notifications
.venv/bin/python probe.py

# decode live telemetry (read-only)
.venv/bin/python kcq.py --secs 10

# set gear 1 = 20 km/h, gear 2 = 40 km/h
.venv/bin/python kcq.py --one-two 20,40

# set gear 3 = 30 km/h, start speed = 0
.venv/bin/python kcq.py --three 30,0

# restore the settings byte to "gear 2 + start mode + MPH"
.venv/bin/python kcq.py --send "aa cc a5 25 00 80 4a ee"

# live speed dashboard with peak tracking (run during a test ride)
.venv/bin/python monitor.py
```

All scripts read the device address from the `SCOOTER_MAC` environment variable, falling
back to the placeholder `AA:BB:CC:DD:EE:FF`:

```bash
export SCOOTER_MAC="AA:BB:CC:DD:EE:FF"   # your scooter's address
```

> **Before writing anything**, capture the `0x56` frame and write the values down. On the
> test unit the factory state was `g1=15 g2=30 g3=25 start=0`, settings byte `0x4A`.

---

## 3. Device discovery and GATT map

### 3.1 Advertising

The device advertises under the name `KCQScooterNN` (two digits, e.g. `KCQScooter03`) with
a **public** address. It does not advertise service UUIDs in the advertisement payload, so
you must scan by name or by address.

### 3.2 Services and characteristics

Only three primary services are exposed:

| Handle | UUID | Description |
|---|---|---|
| `0x0001` | `00001800-0000-1000-8000-00805f9b34fb` | Generic Access |
| `0x000a` | `00001801-0000-1000-8000-00805f9b34fb` | Generic Attribute |
| `0x000e` | `0000fff0-0000-1000-8000-00805f9b34fb` | **vendor service** |

The vendor service, in handle order:

| Handle | Characteristic | Properties | Purpose |
|---|---|---|---|
| `0x000f` | `fff7` | read, **notify** | notification channel |
| `0x0013` | `fff6` | read, write, write-without-response | **command channel** |
| `0x0017` | `fff1` | read, write, write-without-response | password-enabled status |
| `0x001b` | `fff2` | read, write, write-without-response | unused by app; inert in testing |
| `0x001f` | `fff3` | read, write, write-without-response | BLE device name |
| `0x0023` | `fff5` | read, write, write-without-response | connection password (ASCII) |

Each characteristic carries a Client Characteristic Configuration descriptor
(`0x2902`) and a Characteristic User Description (`0x2901`). The user descriptions are
**generic placeholders** — they read `"Characteristic 1"` … `"Characteristic 6"` and carry
no useful information:

| Characteristic | CCCD handle | User description handle | Value |
|---|---|---|---|
| `fff7` | `0x0011` | `0x0012` | `Characteristic 1` |
| `fff6` | `0x0015` | `0x0016` | `Characteristic 2` |
| `fff1` | `0x0019` | `0x001a` | `Characteristic 3` |
| `fff2` | `0x001d` | `0x001e` | `Characteristic 4` |
| `fff3` | `0x0021` | `0x0022` | `Characteristic 5` |
| `fff5` | `0x0025` | `0x0026` | `Characteristic 6` |

> **BlueZ trap.** BlueZ resolves these short UUIDs against its *assigned numbers* database
> and reports nonsense names — `fff1` shows as "ICCE Digital Key", `fff2` as "Aliro",
> `fff3` as "FiRa Consortium", `fff5` as "Car Connectivity Consortium", `fff6` as
> "Matter Profile ID", `fff7` as "Zigbee Direct". These are collisions with newer assigned
> UUIDs. Ignore them completely.

### 3.3 Characteristic values at rest

| Characteristic | Read value | Meaning |
|---|---|---|
| `0x2a00` (Device Name) | `4b 43 51 53 63 6f 6f 74 65 72 30 33 00` | `KCQScooter03\0` |
| `0x2a01` (Appearance) | `00 00` | unspecified |
| `0x2a04` (Preferred Conn Params) | `08 00 0a 00 00 00 90 01` | min 10 ms, max 12.5 ms, latency 0, timeout 4 s |
| `0x2a05` (Service Changed) | `01 00 ff ff` | standard |
| `0x2ac9` (RPA Only) | *(empty)* | |
| `fff5` (password) | `30 30 30 30 30 30` | ASCII `000000` |
| `fff1` (password status) | `00` | password **disabled** |
| `fff6`, `fff7`, `fff2`, `fff3` | *(empty)* | |

### 3.4 Connection and authentication

There is **no pairing, bonding or encryption** required. Connect, enable notifications on
`fff7`, and you are immediately able to issue commands.

The password feature exists but is off by default:

- `fff1` reads `0x00` → password disabled. If enabled it would read `0x01`.
- `fff5` holds the password as **ASCII bytes**, e.g. `000000`.
- To enable/disable, the app writes a single byte `0x01`/`0x00` to `fff1`, sleeps 200 ms,
  then writes the ASCII password to `fff5`.

**If a unit has a password set**, you must write the password to `fff5` before commands
will be accepted. The reference app does this automatically on connect.

### 3.5 Connection timing

The device emits an initial burst of config frames shortly after the notification
descriptor is written:

- `0x55` telemetry: continuous, **~14 Hz** (210 frames captured in 15.0 s).
- `0x56` gear config: first arrives **~2.2 s** after subscribe, then repeats every ~2–5 s.
- `0x57` limit ranges: same cadence, interleaved with `0x56`.

> **If you subscribe late you will miss `0x56` and `0x57` entirely.** Subscribe to `fff7`
> as the very first operation after the connection completes, before enumerating anything
> else.

---

## 4. Frame layer

Two completely different frame formats share the same `0xAA` first byte. Confusing them is
the single most common source of bugs.

### 4.1 Notifications (device → host)

```
 byte:   0     1       2 .......... n-2   n-1
       +----+----+---------------------+-----+-----+
       | AA | TT |     payload         | XOR | 5D  |
       +----+----+---------------------+-----+-----+
```

| Field | Description |
|---|---|
| `AA` | header |
| `TT` | frame type: `0x55` telemetry, `0x56` gear config, `0x57` limit ranges |
| payload | type-specific, offsets 2 … n-3 |
| XOR | XOR of every byte from offset **2** up to but not including the XOR byte |
| `5D` | **fixed tail byte**, constant on every frame ever observed |

Frame length is **16 bytes** for all three types. The last two bytes are *not* a CRC16 —
verified against hundreds of frames.

```
xor = 0
for b in frame[2:-2]: xor ^= b
assert xor == frame[-2]
assert frame[-1] == 0x5D
```

### 4.2 Commands (host → device)

```
 byte:   0   1    2      3    4     5     6    7
       +----+----+------+----+----+-----+-----+----+
       | AA | CC | SIG  | d1 | d2 | XOR | SUM | EE |
       +----+----+------+----+----+-----+-----+----+
```

| Field | Description |
|---|---|
| `AA CC` | command header — **not** `AA 55` |
| `SIG` | command selector: `A5`, `A7`, `A8` |
| `d1` | data byte 1 |
| `d2` | data byte 2 |
| `XOR` | `d1 ^ SIG` |
| `SUM` | `(d1 + SIG + XOR) & 0xFF` |
| `EE` | fixed tail |

**`d2` is not covered by any checksum.** Verified by writing arbitrary values into `d2`
on every command — all accepted. Only `d1`, `SIG` and `XOR` participate in `SUM`.

Commands are 8 bytes. The device accepts them on both the write-with-response and
write-without-response paths; the reference app uses write-without-response.

### 4.3 Worked checksum examples

`A7` with `g1 = 40 (0x28)`, `g2 = 40 (0x28)`:

```
SIG = A7
XOR = 28 ^ A7        = 8F
SUM = (28 + A7 + 8F) & FF = 15E & FF = 5E
frame = AA CC A7 28 28 8F 5E EE
```

`A5` with settings `0x25`, flags `0x00`:

```
SIG = A5
XOR = 25 ^ A5        = 80
SUM = (25 + A5 + 80) & FF = 14A & FF = 4A
frame = AA CC A5 25 00 80 4A EE
```

Telemetry frame `AA 55 4E 01 67 1C 02 00 64 00 08 4A 1A 00 0A 5D`:

```
XOR over d[2..13] = 4E^01^67^1C^02^00^64^00^08^4A^1A^00 = 0A   ✓ matches
tail = 5D                                                       ✓
```

All eight example frames in this document were programmatically validated.

---

## 5. Telemetry — notification type `0x55`

16-byte frame, emitted ~14 Hz. Multi-byte fields are **little-endian**.

### 5.1 Field map

| Offset | Bytes | Field | Scale / notes |
|---|---|---|---|
| 0 | 1 | header | `0xAA` |
| 1 | 1 | type | `0x55` |
| 2–3 | 2 | **speed** | **0.1 km/h**, LE → `((d[3] << 8) \| d[2]) / 10.0` |
| 4–5 | 2 | total odometer | 0.01 km, LE → `(d[4] \| (d[5] << 8)) / 100.0` |
| 6–7 | 2 | trip distance | 0.01 km, LE |
| 8 | 1 | battery | percent, 0–100 |
| 9 | 1 | fault bits | see 5.2 |
| 10 | 1 | status bits | see 5.3 |
| 11 | 1 | settings byte | see 5.4 |
| 12–13 | 2 | ride time | seconds, LE |
| 14 | 1 | XOR checksum | |
| 15 | 1 | tail | `0x5D` |

> ### ⚠️ Speed is 0.1 km/h, not km/h
> This is the most expensive mistake to make. Decoding `d[2..3]` as whole km/h turns a
> 33.4 km/h ride into "334 km/h". The reference app divides by 10
> (`Utils.getUnitData(speed, 1, 10, isMph)`), and so must you.
>
> At rest speed reads `0`. During a full-throttle run from a standstill the raw values
> climb `33 → 52 → 96 → 135 → 171 → 195 → 225 → 255 → 265 → 284 → 308 → 311 → 318 → 323
> → 331 → 334`, i.e. 3.3 → 33.4 km/h.

### 5.2 Fault bits (`d[9]`), LSB first

| Bit | Name |
|---|---|
| 0 | hall fault |
| 1 | MOS fault |
| 2 | brake fault |
| 3 | turn fault |
| 4 | undervoltage fault |
| 5 | comm fault |
| 6 | overvoltage fault |
| 7 | zero fault |

On a healthy unit this byte is `0x00` at all times, including while riding.

### 5.3 Status bits (`d[10]`), LSB first

| Bit | Meaning | Observed |
|---|---|---|
| 0 | block fault | 0 |
| 1 | cruise control active | 0 |
| 2 | drive / motor engaged | 0 |
| 3 | **cycling (moving)** | toggles `0`↔`1` with motion |
| 4 | auto power-down | 0 |
| 5 | third gear active | 0 on 2-gear units |
| 6 | temperature state | 0 |
| 7 | — | 0 |

Bit 3 is what the app uses to refuse speed changes while riding
(`tip_is_cycling_not_setting`).

### 5.4 Settings byte (`d[11]`), LSB first

| Bits | Field | Notes |
|---|---|---|
| 0–1 | **gear** | `1` = gear 1, `2` = gear 2, `3` = gear 3; `0` is normalised to `1` |
| 2 | cruise control enabled | |
| 3 | **start mode** | `1` = zero-start (throttle from standstill), `0` = kick-start |
| 4 | headlight | |
| 5 | taillight | |
| 6 | **unit** | `1` = MPH, `0` = KM/H |
| 7 | **lock** | anti-theft; `1` = locked |

The gear field is simply the binary gear number: `1 = 0b01`, `2 = 0b10`, `3 = 0b11`.
Bit 0 is therefore `gear & 1`.

### 5.5 Worked decode

```
aa 55 4e 01 67 1c 02 00 64 00 08 4a 1a 00 0a 5d
   -- -- ----- ----- ----- -- -- -- -- -- ----- -- --
   |  |   |     |     |    |  |  |  |  |    |  |  +-- tail 5D
   |  |   |     |     |    |  |  |  |  |    |  +----- XOR 0A (validated)
   |  |   |     |     |    |  |  |  |  |    +-------- ride time 26 s
   |  |   |     |     |    |  |  |  |  +------------- settings 0x4A
   |  |   |     |     |    |  |  |  +---------------- status 0x08 (moving)
   |  |   |     |     |    |  |  +------------------- faults 0x00
   |  |   |     |     |    |  +---------------------- battery 100 %
   |  |   |     |     |    +------------------------- trip 0x0002 = 0.02 km
   |  |   |     +-----+------------------------------ odometer 0x1C67 = 72.71 km
   |  |   +------------------------------------------ speed 0x014E = 334 = 33.4 km/h
   |  +---------------------------------------------- type 0x55
   +------------------------------------------------- header 0xAA
```

Settings `0x4A` = `0100 1010` → bits 1, 3, 6 set → **gear 2, start mode on, MPH**,
everything else off.

---

## 6. Gear config — notification type `0x56`

Sent periodically and **immediately after any speed write** (this is your acknowledgement
that a write landed).

### 6.1 Field map

| Offset | Field | Notes |
|---|---|---|
| 0–1 | header / type | `AA 56` |
| 2 | pedestrian-mode bits | not exercised on this unit |
| 3 | **unknown, constant `0x23`** | see 6.3 — almost certainly the ESC speed cap |
| 4 | **unknown, state byte** | varies `0x80`, `0x8D`, `0x15`, `0x00` |
| 5 | **gear 1 speed** | km/h |
| 6 | **gear 2 speed** | km/h |
| 7 | **gear 3 speed** | km/h |
| 8 | **start speed** | km/h |
| 9–13 | always `00` in every capture | |
| 14 | XOR checksum | |
| 15 | tail `0x5D` | |

All speed values are **always km/h on the wire**, even when the unit is set to MPH. The
reference app multiplies by 1.6 before sending when the unit bit is set:

```java
if (CacheData.shared().uint == 1) {           // unit == MPH
    mDeviceMgr.setOneTwoSpeed(mOneSpeed, Math.round(i * 1.6f));
} else {
    mDeviceMgr.setOneTwoSpeed(mOneSpeed, i);
}
```

### 6.2 Worked decode

```
aa 56 00 23 15 14 32 32 00 00 00 00 00 00 22 5d
         |  |  |  |  |  |  |  |  |  |  |  |  |  |
         |  |  |  |  |  |  |  |  |  |  |  |  |  +-- tail
         |  |  |  |  |  |  |  |  |  |  |  |  +----- XOR 0x22 (validated)
         |  |  |  |  |  |  |  |  +--+--+--+-------- zero padding
         |  |  |  |  +--+--+------------------------ start speed = 0
         |  +--+--+------------------------------- g1=20  g2=50  g3=50 km/h
         +---------------------------------------- unknown 0x15
```

### 6.3 Offset 3 — the 35 km/h ceiling (strong inference)

Offset 3 was **`0x23` in every single frame captured across the entire investigation** —
through dozens of speed writes, settings scrambles, factory-restore flags, a full
256-signature fuzz sweep, and a live ride. It never changed once.

`0x23` = **35 decimal**.

Independent measurements:

| Measurement | Result |
|---|---|
| `d[3]` value | 35 |
| User-reported top speed at `g2 = 40` | 22 mph = **35.4 km/h** |
| Telemetry peak at `g2 = 50` (full-throttle sweep) | **33.4 km/h** (sagging under load) |

Three independent numbers landing on 35 km/h is not a coincidence. **The ESC almost
certainly holds a hard-coded 35 km/h maximum in this byte.**

It is **not writable by any command** — the 256-signature sweep found nothing that touched
it, and the app never reads or writes it. Treat it as read-only telemetry.

> This is the single most useful conclusion in this document: it explains why writing 40,
> 50 or 65 km/h into the gear-speed fields changes nothing above ~35 km/h, and why the
> advertised `0x57` "max" of 30 is irrelevant.

---

## 7. Limit ranges — notification type `0x57`

Advisory range data, used by the app to bound its sliders.

### 7.1 Field map

| Offset | Field |
|---|---|
| 0–1 | header / type `AA 57` |
| 2–5 | always `00` in every capture |
| 6 | state byte (varies: `0x00`, `0x01`, `0x14`) |
| 7 | state byte (varies: `0x01`, `0x04`, `0x11`) |
| 8 | **gear 1 min** |
| 9 | **gear 1 max** |
| 10 | **gear 2 min** |
| 11 | **gear 2 max** |
| 12 | **gear 3 min** |
| 13 | **gear 3 max** |
| 14 | XOR checksum |
| 15 | tail `0x5D` |

Observed on the test unit:

```
aa 57 00 00 00 00 01 04 14 14 19 1e 19 19 02 5d
                        |  |  |  |  |  |  |  |
                        |  |  |  |  |  |  |  +-- tail
                        |  |  |  |  |  |  +----- XOR 0x02 (validated)
                        |  |  |  |  |  +-------- g3 max = 25
                        |  |  |  |  +----------- g3 min = 25
                        |  |  |  +-------------- g2 max = 30
                        |  |  +----------------- g2 min = 25
                        |  +-------------------- g1 max = 20
                        +----------------------- g1 min = 20
```

So: `g1 20..20`, `g2 25..30`, `g3 25..25` km/h.

### 7.2 These are advisory only

**The firmware does not enforce these values.** Writing 40, 50 and 65 km/h into gear 2 was
accepted and echoed back by `0x56` every time, and the scooter physically exceeded the
"max" of 30 (it hit 35 km/h).

The ranges only exist so the app can bound its three `BubbleSeekBar` sliders. A fixed
`min == max` (as on gears 1 and 3) is how the app decides to hide a slider entirely:

```java
if (CacheData.shared().uint == 1) {   // MPH
    if (speedInfo.getOneMinSpeed() == speedInfo.getOneMaxSpeed()) {
        seekBarSpeed1.getConfigBuilder()
            .min(kmToMph(min) - 0.1f)
            .max(kmToMph(max) + 0.1f)   // tiny range so the bar is effectively fixed
            .progress(kmToMph(mOneSpeed)).build();
    } else {
        seekBarSpeed1.getConfigBuilder()
            .min(kmToMph(min)).max(kmToMph(max))
            .progress(kmToMph(mOneSpeed)).build();
    }
}
```

### 7.3 Observed variations of the state bytes

Across the investigation, offsets 6 and 7 took these combinations:

| `d[6]` | `d[7]` | Context |
|---|---|---|
| `0x00` | `0x01` | idle / baseline |
| `0x14` | `0x01` | after a gear-speed write |
| `0x01` | `0x01` | idle |
| `0x01` | `0x11` | immediately after an `A9` probe |
| `0x01` | `0x04` | during the fuzz sweep |

**The six limit bytes (`d[8]`–`d[13]`) never changed in any of these transitions.** The
`A9` signature reliably flips `d[7]` between `0x01` and `0x11`, which is the only
remaining unexplained behaviour in the protocol (see §13.4).

---

## 8. Command reference

All commands are 8 bytes on characteristic `fff6`. `d2` is never checksummed.

### 8.1 `A7` — gear 1 and gear 2 speed

```
AA CC A7 <g1> <g2> <g1 ^ A7> <(g1 + A7 + (g1 ^ A7)) & 0xFF> EE
```

| Field | Meaning |
|---|---|
| `g1` | gear 1 maximum speed, km/h |
| `g2` | gear 2 maximum speed, km/h |

Examples:

```
g1=20, g2=50   ->  AA CC A7 14 32  B3  6E  EE
g1=40, g2=40   ->  AA CC A7 28 28  8F  5E  EE
g1=15, g2=30   ->  AA CC A7 0F 1E  A8  5E  EE
```

The device acknowledges with a fresh `0x56` frame within a few hundred milliseconds.

**Value encoding.** The app builds this byte with `intToHex(i)` then `hexToByte(...)`,
which is equivalent to `(byte) i` for `1 ≤ i ≤ 255`. Consequences:

- `i = 0` throws `NumberFormatException` in the app (`intToHex(0)` returns an empty
  string), so **the app can never send 0**. Over raw BLE it is accepted and stores 0.
- `i > 255` wraps: `intToHex(300)` = `"12C"`, parsed as hex = 300, cast to byte = `44`.
- Negative or absent values are not meaningful.

### 8.2 `A8` — gear 3 speed and start speed

```
AA CC A8 <g3> <start> <g3 ^ A8> <(g3 + A8 + (g3 ^ A8)) & 0xFF> EE
```

| Field | Meaning |
|---|---|
| `g3` | gear 3 maximum speed, km/h |
| `start` | start speed, km/h (0 on the test unit) |

Examples:

```
g3=25, start=0  ->  AA CC A8 19 00  B1  72  EE
g3=40, start=0  ->  AA CC A8 28 00  80  50  EE
```

> **Note the asymmetry:** the checksum uses `d1` (`g3`) only. The `start` byte can be
> changed freely without recomputing anything.

### 8.3 `A5` — settings byte

```
AA CC A5 <settings> <flags> <settings ^ A5> <(settings + A5 + (settings ^ A5)) & 0xFF> EE
```

This is the only command with non-obvious semantics. Read §9 before using it.

---

## 9. The `A5` settings-byte bit shift

### 9.1 The rule

The settings byte is **not** applied verbatim. Measured on five independent writes:

> **Written bit *i* appears at reported bit *i+1*.**
> Bit 0 of the reported byte is derived from the scooter's gear state (`gear & 1`).

To make the scooter report settings byte `R`, write `R >> 1`.

### 9.2 Derivation table

| Written | Written bits | Reported | Reported bits | Check |
|---|---|---|---|---|
| `0x25` | 0, 2, 5 | `0x4A` | 1, 3, 6 | `i → i+1` ✓ |
| `0x52` | 1, 4, 6 | `0xA5` | 0, 2, 5, 7 | `i → i+1` ✓ |
| `0x4A` | 1, 3, 6 | `0x95` | 0, 2, 4, 7 | `i → i+1` ✓ |
| `0x02` | 1 | `0x85` | 0, 2, 7 | `i → i+1` ✓ |
| `0x00` | — | `0x01` | 0 | gear-derived bit 0 ✓ |

Bit 0 of the report is `gear & 1`, so it is `1` for gear 1 and gear 3 and `0` for gear 2.
That is why writing `0x25` (which sets written bit 0 → reported bit 1 → gear 2) yields a
report with bit 0 clear.

Some bits are **stateful** and linger when not explicitly driven — observed on the lock bit
(7) and cruise bit (2). Always send a complete intended byte rather than assuming a
read-modify-write will behave.

### 9.3 Practical recipes

| Goal | Reported byte | Write | Frame |
|---|---|---|---|
| gear 2 + start mode + MPH, lights off, unlocked | `0x4A` | `0x25` | `AA CC A5 25 00 80 4A EE` |
| everything off / **unlock** | `0x01` | `0x00` | `AA CC A5 00 00 A5 4A EE` |
| gear 1 + start mode + MPH | `0x49` | `0x24` | `AA CC A5 24 00 81 4A EE` |

### 9.4 The `<flags>` byte

`d2` is a second bitfield the app calls `SettingInfo2`, built as an 8-character string and
reversed exactly like the settings byte:

| Bit | Field |
|---|---|
| 0 | constant `0` |
| 1 | pedestrian mode |
| 2 | pedestrian view |
| 3 | constant `0` |
| 4 | third-gear view |
| 5 | third gear active |
| 6 | disconnect |
| 7 | **recover (factory restore)** |

> ### ⚠️ `flags = 0x80` is a factory restore
> Setting bit 7 makes the frame a *restore factory settings* command, not a normal write.
> During this investigation it scrambled the settings byte into `0x95` (lock + headlight +
> cruise + km/h). Use `0x00` unless you actually intend a reset.

### 9.5 Why this happens — the app's off-by-one

The reference app is internally inconsistent. `SettingInfo.toString()` builds the bit
string in this order:

```java
public String toString() {
    return getSetting(!this.gear)          // index 0
         + getSetting(this.steadyCruise)   // index 1
         + getSetting(this.startMode)      // index 2
         + getSetting(this.headlight)      // index 3
         + getSetting(this.taillight)      // index 4
         + getSetting(this.unit)           // index 5
         + getSetting(this.lockCar)        // index 6
         + "0";                            // index 7
}
```

…but the *parser* reads the same byte with every field one position higher:

```java
settingInfo.setSteadyCruise(isTrue2(b[2..3]));  // index 2
settingInfo.setStartMode  (isTrue2(b[3..4]));  // index 3
settingInfo.setHeadlight  (isTrue2(b[4..5]));  // index 4
settingInfo.setTaillight  (isTrue2(b[5..6]));  // index 5
settingInfo.setUnit       (isTrue2(b[6..7]));  // index 6
settingInfo.setLockCar    (isTrue2(b[7..8]));  // index 7
```

So the write layout is one bit lower than the read layout — exactly the shift observed on
the wire. This is a genuine bug in the shipping app, and it is why writing back a value you
just read scrambles the byte.

---

## 10. How the shipping app implements it (decompiled)

### 10.1 `com/kcq/kcqscooter/device/RequestPackage.java`

The frame builder. Heads, signatures and tail are all negative decimal literals
(`-86 = 0xAA`, `-52 = 0xCC`, `-91 = 0xA5`, `-89 = 0xA7`, `-88 = 0xA8`, `-18 = 0xEE`).

```java
private byte[] mHead    = {-86, -52};   // AA CC
private byte signature    = -91;        // A5
private byte signatureA7  = -89;        // A7
private byte signatureA8  = -88;        // A8
private byte mTail        = -18;        // EE
```

Gear 1 / 2 speed:

```java
public byte[] settingOneTwoSpeed(int i, int i2) {
    this.totalData.clear();
    this.totalData.add(Byte.valueOf(this.mHead[0]));         // AA
    this.totalData.add(Byte.valueOf(this.mHead[1]));         // CC
    this.totalData.add(Byte.valueOf(this.signatureA7));      // A7
    byte hexToByte = Utils.hexToByte(Utils.intToHex(i));     // (byte) i
    this.totalData.add(Byte.valueOf(hexToByte));
    this.totalData.add(Byte.valueOf(Utils.hexToByte(Utils.intToHex(i2))));
    byte exclusive = Utils.exclusive(hexToByte, this.signatureA7);
    this.totalData.add(Byte.valueOf(exclusive));
    this.totalData.add(Byte.valueOf(
        Utils.sumCheck(new byte[]{hexToByte, this.signatureA7, exclusive})));
    this.totalData.add(Byte.valueOf(this.mTail));            // EE
    ...
}
```

Gear 3 / start speed is identical with `signatureA8` and reads `d1 = i`, `d2 = i2`.

Settings (`getData`) — note the two data bytes and the restore flag:

```java
public byte[] getData(String str, int i, int i2, boolean z, int i3, boolean z2) {
    this.totalData.add(this.mHead[0]);   // AA
    this.totalData.add(this.mHead[1]);   // CC
    this.totalData.add(this.signature);  // A5

    byte settingData = Utils.getSettingData(str, i, i2, Utils.getSetting(z));

    this.settingInfo2.setRecover(false);
    this.settingInfo2.setDisconnect(false);
    this.settingInfo2.setThirdGearView(z2);
    this.settingInfo2.setPedestrian(i3 == 0);
    this.settingInfo2.setThirdGear(i3 == 3);

    this.totalData.add(Byte.valueOf(settingData));
    this.totalData.add(Byte.valueOf(Utils.bitToByte(this.settingInfo2.toString())));

    byte exclusive = Utils.exclusive(settingData, this.signature);
    this.totalData.add(Byte.valueOf(exclusive));
    this.totalData.add(Byte.valueOf(
        Utils.sumCheck(new byte[]{settingData, this.signature, exclusive})));
    this.totalData.add(Byte.valueOf(this.mTail));
    ...
}
```

### 10.2 `com/kcq/kcqscooter/utils/Utils.java`

The encoding primitives:

```java
public static byte exclusive(byte b, byte b2) { return (byte) (b ^ b2); }

public static byte sumCheck(byte[] bArr) {
    int i = 0;
    for (byte b : bArr) { i += b; }
    return (byte) (i & 255);
}

public static String intToHex(int i) {
    StringBuilder sb = new StringBuilder(8);
    char[] cArr = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    while (i != 0) { sb.append(cArr[i % 16]); i /= 16; }
    return sb.reverse().toString();     // returns "" for i == 0  -> NFE downstream
}

public static byte hexToByte(String str) { return (byte) Integer.parseInt(str, 16); }

public static byte bitToByte(String str) {
    if (str == null) return (byte) 0;
    int length = str.length();
    if (length != 4 && length != 8) return (byte) 0;
    if (length == 8) {
        if (str.charAt(0) == '0') {
            return (byte) Integer.parseInt(str, 2);
        } else {
            return (byte) (Integer.parseInt(str, 2)
                           + android.support.v4.view.InputDeviceCompat.SOURCE_ANY);
        }
    }
    return (byte) Integer.parseInt(str, 2);
}

public static byte getSettingData(String str, int i, int i2, String str2) {
    StringBuffer sb = new StringBuffer(str);
    sb.replace(i, i2, str2);                    // replace chars [i, i2)
    return bitToByte(sb.reverse().toString());  // MSB-first parse -> LSB-first layout
}

public static int byteToSpeed(byte b, byte b2) { return ((b & 255) << 8) | (b2 & 255); }
public static int byteToInt  (byte b, byte b2) { return (b & 255) | ((b2 & 255) << 8); }
public static String byteToBit(byte b) {
    return "" + ((b >> 0) & 1) + ((b >> 1) & 1) + ... + ((b >> 7) & 1);   // LSB first
}
```

`SOURCE_ANY` is `0xff000000`; the addition is a no-op once cast to `byte`, so `bitToByte`
behaves as a plain binary parse.

> Note `byteToSpeed` is **big-endian** (`(b<<8) | b2`) while `byteToInt` is
> **little-endian** (`b | (b2<<8)`). Speed and mileage therefore use opposite byte orders
> within the same frame. This is correct and intentional — do not "fix" it.

### 10.3 `com/kcq/kcqscooter/activity/App.java`

The notification parser. Abridged but complete for the fields that matter:

```java
public void onNotifyData(String str, byte[] bArr) {
    DeviceInfo deviceInfo = new DeviceInfo();
    byte b = bArr[0];
    if (b == -86 && bArr[1] == 85) {                       // AA 55
        deviceInfo.setSpeed(Utils.byteToSpeed(bArr[3], bArr[2]));
        deviceInfo.setTotalMileage(Utils.byteToInt(bArr[4], bArr[5]));
        deviceInfo.setCurrentMileage(Utils.byteToInt(bArr[6], bArr[7]));
        deviceInfo.setElectricity(bArr[8] & 255);

        String byteToBit  = Utils.byteToBit(bArr[9]);      // faults
        String byteToBit2 = Utils.byteToBit(bArr[10]);     // status
        deviceInfo.setCruise(isTrue(byteToBit2.substring(1, 2)));
        deviceInfo.setDrive (isTrue(byteToBit2.substring(2, 3)));
        faultInfo.setCyclingStatus(isTrue(byteToBit2.substring(3, 4)));

        String byteToBit3 = Utils.byteToBit(bArr[11]);     // settings
        int gear = Utils.getGear(byteToBit3.substring(0, 2));
        settingInfo.setSteadyCruise(isTrue2(byteToBit3.substring(2, 3)));
        settingInfo.setStartMode  (isTrue2(byteToBit3.substring(3, 4)));
        settingInfo.setHeadlight  (isTrue2(byteToBit3.substring(4, 5)));
        settingInfo.setTaillight  (isTrue2(byteToBit3.substring(5, 6)));
        settingInfo.setUnit       (isTrue2(byteToBit3.substring(6, 7)));
        settingInfo.setLockCar    (isTrue2(byteToBit3.substring(7, 8)));

        deviceInfo.setCyclingTime(Utils.byteToInt(bArr[12], bArr[13]));
        return;
    }
    if (b == -86 && bArr[1] == 86) {                       // AA 56
        PedestriainInfo p = new PedestriainInfo();
        p.setOneSpeed  (Utils.hex16To10(Utils.byteToHex(bArr[5])));
        p.setTwoSpeed  (Utils.hex16To10(Utils.byteToHex(bArr[6])));
        p.setThreeSpeed(Utils.hex16To10(Utils.byteToHex(bArr[7])));
        p.setStartSpeed(Utils.hex16To10(Utils.byteToHex(bArr[8])));
        return;
    }
    if (b == -86 && bArr[1] == 87) {                       // AA 57
        SpeedInfo s = new SpeedInfo();
        s.setOneMinSpeed  (Utils.hex16To10(Utils.byteToHex(bArr[8])));
        s.setOneMaxSpeed  (Utils.hex16To10(Utils.byteToHex(bArr[9])));
        s.setTwoMinSpeed  (Utils.hex16To10(Utils.byteToHex(bArr[10])));
        s.setTwoMaxSpeed  (Utils.hex16To10(Utils.byteToHex(bArr[11])));
        s.setThreeMinSpeed(Utils.hex16To10(Utils.byteToHex(bArr[12])));
        s.setThreeMaxSpeed(Utils.hex16To10(Utils.byteToHex(bArr[13])));
    }
}
```

`getGear` is worth quoting because its mapping is non-obvious:

```java
public static int getGear(String str) {
    if (str.equals("11")) return 3;
    return (!str.equals("10") && str.equals("01")) ? 2 : 1;
}
// "11" -> 3,  "01" -> 2,  "10" -> 1,  "00" -> 1
```

### 10.4 `com/kcq/kcqscooter/device/DeviceMgr.java`

Command dispatch — this tells you which characteristic each operation uses:

| Method | Characteristic | Command |
|---|---|---|
| `setOneTwoSpeed(g1, g2)` | `fff6` | `A7` |
| `setThreeSpeed(g3, start)` | `fff6` | `A8` |
| `setGear`, `setThireGear`, `setPedestrain`, `setSteadyCruise`, `setStartMode`, `setHeadlight`, `setTaillight`, `setUnit`, `setLockCar`, `closeDevice`, `restoreFactory`, `disConnect` | `fff6` | `A5` |
| `setBleName(str)` | **`fff3`** | raw ASCII, no frame |
| `setPwd(str, enabled)` | **`fff1`** then **`fff5`** | 1 byte, then ASCII |
| `getConnectPwdStatus()` | reads `fff1` | — |
| `getConnectPwd()` | reads `fff5` | — |
| `getSerialNumber()` | reads `2a23` in service `180a` | — |

The `A5` bit-range for each setting (note: these are the *write* indices, one lower than
the read indices — see §9.5):

| Setting | `write(i, i2, z)` |
|---|---|
| steady cruise | `write(1, 2, z)` |
| start mode | `write(2, 3, z)` |
| headlight | `write(3, 4, z)` |
| taillight | `write(4, 5, z)` |
| unit | `write(5, 6, z)` |
| lock car | `write(6, 7, z)` |
| close device | `write(7, 8, z)` |

### 10.5 `com/wm/bluetooth/library/Constants/UUIDConstant.java`

```java
public static final UUID SERVICE_UUID            = UUID.fromString("0000FFF0-...");
public static final UUID WRITE_AND_READ_PWD_STATUS = UUID.fromString("0000FFF1-...");
public static final UUID BLE_NAME_MODIFY         = UUID.fromString("0000FFF3-...");
public static final UUID WRITE_AND_READ_PWD      = UUID.fromString("0000FFF5-...");
public static final UUID WRITE                   = UUID.fromString("0000FFF6-...");
public static final UUID NOTIFY                  = UUID.fromString("0000FFF7-...");
public static final UUID DESCRIPTOR              = UUID.fromString("00002902-...");
public static final UUID SERVICE_DEVICE_INFOMATION = UUID.fromString("0000180a-...");
public static final UUID SYSTEM_ID               = UUID.fromString("00002a23-...");
```

`fff2` is **not referenced anywhere** in the app — it is exposed by the firmware but unused.

---

## 11. Experiment log

Chronological record of everything attempted, with outcomes. Useful if you are wondering
"did they try X?" — yes, probably.

| # | Action | Result |
|---|---|---|
| 1 | Connect, enumerate GATT, subscribe late, capture 15 s | 210 frames, all `0x55`. `0x56`/`0x57` missed because subscription happened after enumeration |
| 2 | Reconnect and subscribe **first** | `0x56`/`0x57` appear at ~2.2 s, repeat every 2–5 s |
| 3 | Read all characteristics | password `000000`, disabled; name `KCQScooter03` |
| 4 | Write `A7` g1=16, g2=30 | accepted; `0x56` reports `16/30/25` |
| 5 | Write `A7` g1=15, g2=32 | accepted |
| 6 | Write `A7` g2=40 | accepted; user measured **22 mph (35.4 km/h)** |
| 7 | Write `A7` g2=50 | accepted |
| 8 | Write `A7` g2=65 | accepted — **no validation whatsoever** |
| 9 | Write `A8` g3=40 | accepted |
| 10 | Restore `15/30/25` | `0x56` byte-identical to the original capture |
| 11 | Set all gears to 40 | accepted; ride still ~22 mph |
| 12 | Set g1=10, g2=40, g3=40 | scooter display showed the new numbers |
| 13 | Set g1=20, g2=30, g3=25 ("max within limits") | ride dropped back to 19 mph — **this was my error**, the 30 "limit" is advisory |
| 14 | Brake + power ×5 combo (from an iScooter T8 forum post) | **no effect** — `0x57` unchanged |
| 15 | Fuzz signatures `A0`–`BF` with payload `00 00` | `A7`/`A8` zeroed the gear speeds; `A5` cleared the settings byte; `A9` flipped `0x57 d[7]`; everything else inert |
| 16 | Fuzz signatures `00`–`9F` | **nothing** |
| 17 | Fuzz signatures `C0`–`FF` | **nothing** |
| 18 | Derive the `A5` mapping (`0x00→0x01`, `0x02→0x85`, `0x4A→0x95`, `0x52→0xA5`, `0x25→0x4A`) | bit *i* → bit *i+1* |
| 19 | Write `A5 0x25` to restore gear 2 + start mode + MPH | **success** — reported `0x4A`, scooter accelerated again |
| 20 | Full-throttle ride with `g2 = 50`, telemetry logged | peak **33.4 km/h**; `d[3]` still `0x23` |

### 11.1 The failure at step 15/16 worth explaining

Clearing the settings byte set **start mode = 0**, which the controller interprets as
*kick-start required*. The throttle then does nothing from a standstill, and the scooter
looks bricked. There were no fault bits, battery was 100 %, and the lock bit was clear —
the only symptom was "no acceleration".

Recovery: `AA CC A5 25 00 80 4A EE`.

---

## 12. Speed unlocking: what works, what doesn't

### 12.1 The BLE speed write genuinely works

| Written (gear 2) | Observed |
|---|---|
| 30 km/h | ~19 mph (30.6 km/h) |
| 40 km/h | ~22 mph (35.4 km/h) |
| 50 km/h | ~21 mph (33.4 km/h peak, telemetry) |
| 65 km/h | not ridden (stored fine) |

Gear 1 was independently confirmed to be enforced: with `g1 = 10` the scooter refused to
exceed ~10 km/h.

So the write path is real, unauthenticated, and has no range validation.

### 12.2 But the motor saturates at ~35 km/h

A full-throttle run at `g2 = 50`, captured from telemetry:

```
 3.3 → 5.2 → 9.6 → 13.5 → 17.1 → 19.5 → 22.5 → 25.5 → 26.5
 → 28.4 → 30.8 → 31.1 → 31.8 → 32.3 → 33.1 → 33.4 km/h  (peak)
```

33.4 km/h under load, versus 35.4 km/h measured by the rider at `g2 = 40`. Both bracket
the constant `d[3] = 0x23 = 35` in the `0x56` frame. **The ESC's own 35 km/h cap is the
ceiling**, and the value you write only matters below it.

### 12.3 Why the app can't reach it either

The app's sliders are bounded by `0x57`, whose gear 2 maximum is **30**. So the stock app
physically cannot express anything above 30 km/h — you need raw BLE to get to 35, and raw
BLE cannot get past 35.

---

## 13. Dead ends — do not repeat these

### 13.1 The 256-signature sweep

Every value `0x00`–`0xFF` was written to `fff6` with a valid checksum and two zero data
bytes, while watching for new frame types and for changes to `0x56`/`0x57`.

| Signature | Effect |
|---|---|
| `A5` | settings byte |
| `A7` | gear 1 / gear 2 speed |
| `A8` | gear 3 / start speed |
| `A9` | flips a state byte in `0x57` (`d[7]`: `0x01` ↔ `0x11`); **no limit changes** |
| all other 252 values | **completely inert** — no reply, no state change, no new frame type |

**No new notification types exist.** The firmware emits exactly `0x55`, `0x56`, `0x57`.

### 13.2 No hidden parameters

There is **no** command for:

- motor current limit
- acceleration / throttle ramp
- wheel diameter or circumference
- motor pole pairs
- sport / turbo / boost mode
- factory or test mode
- battery voltage configuration
- firmware update over this channel

The `0x57` limit values **never changed** under any command in the entire sweep. They are
compiled-in constants.

### 13.3 The app contains no hidden UI

The manifest exposes exactly 18 activities, all ordinary (`MainActivity`,
`SpeedSettingActivity`, `SettingActivity`, `StartModeActivity`, `TroubleshootingActivity`,
`MapActivity`, …). There is no factory/test/debug activity, no wheel-size screen, and no
P-setting menu. The app is a thin client over the three commands in §8.

### 13.4 The one loose end

`A9` reliably changes `0x57 d[7]` from `0x01` to `0x11` without altering any limit. It is
the only unexplained behaviour left. Someone with a logic analyser on the display↔ESC bus
could determine what that flag gates — it is the last thread worth pulling.

### 13.5 The forum combo does nothing here

The widely-cited `hold left brake + press power 5×` unlock (reported for the iScooter T8)
had **zero effect** on this unit: `0x57` was byte-identical before and after. Model-specific
advice should not be assumed portable.

---

## 14. Gotchas and troubleshooting

### 14.1 Numbered list

1. **Speed is 0.1 km/h**, not km/h. Off by 10×.
2. **Command header is `AA CC`; notification header is `AA 55`.** Different first two bytes.
3. **`d2` is not checksummed** — only `d1`, `SIG` and `XOR` are.
4. **Speed is big-endian, mileage is little-endian** in the same frame.
5. **Subscribe to `fff7` before enumerating** or you will never see `0x56`/`0x57`.
6. **Clearing the start-mode bit = kick-start = dead throttle from standstill.** Looks
   exactly like a bricked scooter. Recover with `AA CC A5 25 00 80 4A EE`.
7. **`A5` with `flags = 0x80` is a factory restore**, not a normal write.
8. **The settings byte is written bit-shifted** (written bit *i* → reported bit *i+1*).
   Writing back what you just read scrambles it.
9. **Bit 7 of the settings byte is an anti-theft lock.** A stray byte can immobilise the
   scooter. `AA CC A5 00 00 A5 4A EE` clears it.
10. **`0x57` is a slider bound, not a limit.** Do not treat 30 as a hard cap.
11. **The app overwrites your values** if anyone touches the speed sliders — it clamps back
    into its own 20/25–30/25 ranges.
12. **Power-cycle after writing** if the change does not appear to take; some state is
    latched at boot.
13. **Lift the rear wheel before fuzzing.** An unknown signature could be a motor self-test.
14. **`fff1`/`fff5` are the password.** Writing to them can lock you out of your own scooter.

### 14.2 Symptom → cause table

| Symptom | Likely cause |
|---|---|
| Throttle dead from standstill, no faults | start-mode bit cleared (kick-start) |
| Speed reads 10× too high | decoded as km/h instead of 0.1 km/h |
| `0x56`/`0x57` never arrive | subscribed after GATT enumeration |
| Gear speeds revert to 15/30/25 | app sliders touched, or factory restore flag sent |
| Scooter won't move at all | lock bit set (settings byte bit 7) |
| Settings byte is garbage | wrote a read value without shifting right by 1 |
| Command silently ignored | wrong checksum, or `AA 55` used instead of `AA CC` |

### 14.3 Recovery procedure

If you have scrambled the settings byte:

```
1. AA CC A5 00 00 A5 4A EE      # clear everything (unlock, lights off, gear 1)
2. AA CC A5 25 00 80 4A EE      # gear 2 + start mode + MPH
3. AA CC A7 0F 1E A8 5E EE      # restore factory gear speeds 15 / 30
4. AA CC A8 19 00 B1 72 EE      # restore factory gear 3 = 25, start = 0
```

Step 4's `start` byte does not affect its checksum, so any value is safe there.

---

## 15. Tool reference

All scripts are plain Python + [bleak](https://github.com/hbldh/bleak), no framework.

### 15.1 `probe.py`

Dumps the GATT tree with properties, reads every readable characteristic, then subscribes
to everything notifiable and prints 15 s of raw frames.

```bash
python probe.py <MAC> [seconds]
```

Use this first on an unknown unit to confirm the UUID layout matches.

### 15.2 `kcq.py`

The main client. Decodes live telemetry and can write speeds or raw frames.

```bash
python kcq.py [--secs N] [--send HEX] [--one-two g1,g2] [--three g3,start]
```

| Flag | Effect |
|---|---|
| `--secs N` | how long to capture after writing (default 15) |
| `--send HEX` | write raw bytes to `fff6`, e.g. `"aa cc a5 25 00 80 4a ee"` |
| `--one-two a,b` | write `A7` with gear 1 = a, gear 2 = b |
| `--three a,b` | write `A8` with gear 3 = a, start = b |

Prints each unique frame once, then a summary table with counts.

### 15.3 `monitor.py`

Live speed dashboard for a test ride. Prints once per second and tracks the peak.

```bash
python monitor.py
```

Output:

```
[  12.4s] speed= 28.4 km/h (17.8 mph)  peak= 33.4 km/h (20.9 mph)  batt=100%  odo=72.71km  gearbits=01
```

### 15.4 `fuzz.py`

Sweeps command signatures and reports any that change device state.

```bash
python fuzz.py --lo 0xA0 --hi 0xBF --d1 0 --d2 0 --gap 0.7
```

Captures a baseline, sends each signature with a valid checksum, and prints only
signatures that produced a new frame type or changed a `0x56`/`0x57` frame. `0x55` is
excluded from change detection because its counter bytes change constantly and produce
noise.

> **The sweep is destructive** — `A7` and `A8` with a zero payload will zero your gear
> speeds, and `A5` will rewrite the settings byte. Always restore afterwards.

---

## 16. Reproducing the APK analysis

### 16.1 Obtaining the APK

Google Play does not serve this app in all regions, APKPure is behind a Cloudflare
challenge, and APKMirror does not carry it. The **Aptoide API works unauthenticated**:

```bash
curl "https://ws75.aptoide.com/api/7/app/get/package_name=com.kcq.kcqscooter" -o app.json
```

Response fields of interest:

```
nodes.meta.data.file.path      -> direct APK URL
nodes.meta.data.file.md5sum    -> expected MD5
nodes.meta.data.file.filesize
nodes.meta.data.file.vername   -> "1.5.4"
nodes.meta.data.file.vercode   -> 54
```

```bash
curl -L -o kcq.apk "<path>"
md5sum kcq.apk    # must equal .md5sum
```

### 16.2 Decompiling

```bash
curl -L -o jadx.zip \
  https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
unzip jadx.zip -d jadx
jadx/bin/jadx -d jadx-out --no-res --no-imports kcq.apk
```

`--no-res` is fine — the protocol lives entirely in `classes.dex`. Expect ~2,200 Java
files and a handful of decompiler errors; they do not affect the BLE classes.

### 16.3 Where to look

Paths relative to `jadx-out/sources/`:

| File | Contents |
|---|---|
| `com/kcq/kcqscooter/device/RequestPackage.java` | **frame builders, checksums, signatures — start here** |
| `com/kcq/kcqscooter/device/DeviceMgr.java` | command dispatch, characteristic per operation |
| `com/kcq/kcqscooter/activity/App.java` | **notification parser — every telemetry field** |
| `com/kcq/kcqscooter/activity/SpeedSettingActivity.java` | per-gear sliders, mph↔km/h conversion, riding guard |
| `com/kcq/kcqscooter/utils/Utils.java` | `sumCheck`, `exclusive`, `bitToByte`, `intToHex`, `byteToSpeed` |
| `com/kcq/kcqscooter/entry/SettingInfo.java` | settings byte bit-string layout (the off-by-one source) |
| `com/kcq/kcqscooter/entry/SettingInfo2.java` | flags byte layout incl. restore bit |
| `com/wm/bluetooth/library/Constants/UUIDConstant.java` | UUID map |

### 16.4 APK contents worth knowing

| Component | Note |
|---|---|
| `classes.dex` (5.7 MB) | all app logic; single dex |
| `lib/*/libBaiduMapSDK_*.so` | Baidu Maps, ~20 MB across ABIs — **not protocol related** |
| `lib/*/libmmkv.so` | Tencent MMKV key-value store |
| `assets/cfg/a/mode_1`, `mode_2` | Baidu map rendering data — **not firmware, not mode config** |

The `assets/cfg/a/mode_1` / `mode_2` directories are a tempting false positive. They are
Baidu map style resources (`.rs` / `.sty` files), not scooter firmware.

---

## 17. Hardware: if you want actual more speed

The BLE layer is exhausted. The 35 km/h cap is in the ESC. Options, cheapest first:

1. **Shunt mod** — bridge part of the current-sense shunt inside the controller. This is
   the only thing that addresses "peppier" directly: it raises the current limit, giving
   harder launch and better hill climbing, plus a small top-speed gain. It pushes the
   motor, BMS and wiring past their design margin, and a 350 W-class hub motor heat-soaks
   quickly. Voids any warranty.
2. **Larger wheels** — a hub motor is RPM-limited, so more diameter is free speed
   (roughly +15 % going 8.5" → 10"), subject to fork and brake clearance.
3. **48 V pack** — ~33 % more RPM at the same current. **Only** if the controller's
   capacitors are rated 63 V. Check the cap markings before connecting anything; a 50 V
   cap will pop.
4. **Aftermarket controller + display** — the only route to genuine P-settings
   (speed percentage, acceleration strength, wheel size). Note that an "open" controller
   may not talk to the stock display; buy them as a matched set.

**Before buying anything:** the `0x56 d[3] = 0x23` constant suggests the ESC firmware
enforces 35 km/h in software, not just electrically. If that is true, a shunt mod buys
torque but not top speed, and only a controller replacement lifts the cap.

---

## Appendix A — raw frame captures

### A.1 Factory state (odometer 72.64 km)

```
aa 55 00 00 60 1c 00 00 64 00 00 49 00 00 51 5d
aa 56 00 23 80 0f 1e 19 00 00 00 00 00 00 ab 5d
aa 57 00 00 00 00 00 01 14 14 19 1e 19 19 06 5d
```

Decoded: speed 0, odo 72.64 km, battery 100 %, settings `0x49` (gear 1, start mode, MPH);
gear speeds **15 / 30 / 25**, start 0; limits **20..20 / 25..30 / 25..25**.

### A.2 After writing `A7` g1=16

```
aa 56 00 23 80 10 1e 19 00 00 00 00 00 00 b4 5d
```

`g1` became 16 — confirms the write path.

### A.3 After writing `A7` g2=40

```
aa 56 00 23 8d 0f 28 19 00 00 00 00 00 00 90 5d
```

`g2` = `0x28` = 40. Note `d[4]` changed `0x80` → `0x8D`; it later returned to `0x80`.

### A.4 After writing `A7` g2=65

```
aa 56 00 23 80 0f 41 19 00 00 00 00 00 00 f4 5d
```

`g2` = `0x41` = 65 — accepted with no validation.

### A.5 After writing `A8` g3=40

```
aa 56 00 23 80 0f 41 28 00 00 00 00 00 00 c5 5d
```

`g3` = `0x28` = 40.

### A.6 Mid-ride, `g2 = 50` (peak of the acceleration sweep)

```
aa 55 4e 01 67 1c 02 00 64 00 08 4a 1a 00 0a 5d
```

33.4 km/h, 72.71 km, 0.02 km trip, 100 %, moving, settings `0x4A`.

### A.7 Settings byte `0x95` (lock + headlight + cruise + km/h)

```
aa 55 00 00 65 1c 00 00 64 00 00 95 0e 00 86 5d
```

This is the state produced by sending `A5` with `flags = 0x80` (the factory-restore flag).

### A.8 Restored via `A5 0x25`

```
aa 55 4f 01 66 1c 01 00 64 00 08 4a 16 00 05 5d
```

Settings `0x4A` — gear 2, start mode, MPH. Scooter accelerating normally again.

### A.9 `0x57` variations observed

```
aa 57 00 00 00 00 00 01 14 14 19 1e 19 19 06 5d   # idle
aa 57 00 00 00 00 14 01 14 14 19 1e 19 19 12 5d   # post gear write
aa 57 00 00 00 00 01 01 14 14 19 1e 19 19 07 5d   # idle
aa 57 00 00 00 00 01 11 14 14 19 1e 19 19 17 5d   # post A9 probe
aa 57 00 00 00 00 01 04 14 14 19 1e 19 19 02 5d   # during fuzz
```

Limits `d[8]`–`d[13]` identical in all five.

---

## Appendix B — settings byte state history

Every distinct settings byte observed, with decode:

| Byte | Binary | Gear | Cruise | Start | Head | Tail | Unit | Lock |
|---|---|---|---|---|---|---|---|---|
| `0x49` | `01001001` | 1 | 0 | 1 | 0 | 0 | MPH | 0 |
| `0x4A` | `01001010` | 2 | 0 | 1 | 0 | 0 | MPH | 0 |
| `0x01` | `00000001` | 1 | 0 | 0 | 0 | 0 | KM/H | 0 |
| `0x05` | `00000101` | 1 | 1 | 0 | 0 | 0 | KM/H | 0 |
| `0x85` | `10000101` | 1 | 1 | 0 | 0 | 0 | KM/H | 1 |
| `0x95` | `10010101` | 1 | 1 | 0 | 1 | 0 | KM/H | 1 |
| `0xA5` | `10100101` | 1 | 1 | 0 | 0 | 1 | KM/H | 1 |

`0x49` and `0x4A` are the only sane states. Everything else was produced by probe writes.

---

## Appendix C — reference implementation

Minimal Python, no dependencies beyond `bleak`.

```python
import asyncio
from bleak import BleakClient

NOTIFY = "0000fff7-0000-1000-8000-00805f9b34fb"
WRITE  = "0000fff6-0000-1000-8000-00805f9b34fb"


def command(sig: int, d1: int, d2: int) -> bytes:
    """Build an 8-byte command frame. d2 is not checksummed."""
    body = [0xAA, 0xCC, sig, d1 & 0xFF, d2 & 0xFF]
    x = body[3] ^ sig
    s = (body[3] + sig + x) & 0xFF
    return bytes(body + [x, s, 0xEE])


def set_gear_1_2(g1: int, g2: int) -> bytes:
    return command(0xA7, g1, g2)


def set_gear_3_start(g3: int, start: int) -> bytes:
    return command(0xA8, g3, start)


def set_settings(reported: int, flags: int = 0x00) -> bytes:
    """`reported` is the byte you want to see in d[11]. Writes are shifted right by 1."""
    return command(0xA5, reported >> 1, flags)


def decode_status(d: bytes) -> dict:
    assert d[0] == 0xAA and d[1] == 0x55
    s = d[11]
    return {
        "speed_kmh":   ((d[3] << 8) | d[2]) / 10.0,     # 0.1 km/h units
        "odometer_km": ((d[5] << 8) | d[4]) / 100.0,    # 0.01 km units
        "trip_km":     ((d[7] << 8) | d[6]) / 100.0,
        "battery":     d[8],
        "faults":      d[9],
        "moving":      bool(d[10] & 0x08),
        "gear":        s & 0x03,
        "cruise":      bool(s & 0x04),
        "start_mode":  bool(s & 0x08),
        "headlight":   bool(s & 0x10),
        "taillight":   bool(s & 0x20),
        "mph":         bool(s & 0x40),
        "locked":      bool(s & 0x80),
        "ride_time_s": (d[13] << 8) | d[12],
    }


def decode_gear_config(d: bytes) -> dict:
    assert d[0] == 0xAA and d[1] == 0x56
    return {
        "esc_max_kmh": d[3],          # constant 0x23 = 35
        "state":       d[4],
        "g1": d[5], "g2": d[6], "g3": d[7], "start": d[8],
    }


def decode_limits(d: bytes) -> dict:
    assert d[0] == 0xAA and d[1] == 0x57
    return {
        "g1": (d[8],  d[9]),
        "g2": (d[10], d[11]),
        "g3": (d[12], d[13]),
    }


async def main(mac: str):
    async with BleakClient(mac) as c:
        def on_frame(_h, data):
            d = bytes(data)
            if d[0] != 0xAA:
                return
            if d[1] == 0x55:
                print(decode_status(d))
            elif d[1] == 0x56:
                print("GEARCFG", decode_gear_config(d))
            elif d[1] == 0x57:
                print("LIMITS ", decode_limits(d))

        await c.start_notify(NOTIFY, on_frame)   # FIRST, before anything else
        await asyncio.sleep(1.0)
        await c.write_gatt_char(WRITE, set_gear_1_2(20, 40), response=False)
        await asyncio.sleep(5.0)


asyncio.run(main("<MAC>"))
```

---

## Appendix D — app version history

Only three builds are publicly available (Aptoide):

| Version | versionCode | Published |
|---|---|---|
| 1.5.4 | 54 | 2026-10-15 |
| 1.5.3 | 53 | 2026-01-06 |
| 1.5.2 | 52 | 2026-02-07 |

There is no newer Android build with additional features. The iOS App Store listing
mentions a 2.0.1 with "set the top speed of the gear" and "remote upgrade", but the
Android 1.5.4 already contains the per-gear speed setting, and no remote-upgrade code
path was found in `classes.dex`.

---

## Disclaimer

Reverse engineering performed on hardware owned by the author, for interoperability and
repair. Writing to the controller can immobilise the vehicle or damage the motor, BMS or
wiring. Unlocking speed may make the vehicle illegal to ride on public roads — in most
jurisdictions e-scooters are capped at 25 km/h / 15.5 mph. You are responsible for what you
do with this.

---

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it, sell it; just keep the copyright
notice.

The APK referenced in §16 is **not** included in this repository and remains the property of
its publisher. It is fetched at build/analysis time from a public mirror purely for
interoperability research.
