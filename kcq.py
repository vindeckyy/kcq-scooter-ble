import asyncio, sys, time, argparse, os
from bleak import BleakClient, BleakScanner

ADDR = os.environ.get("SCOOTER_MAC", "AA:BB:CC:DD:EE:FF")
NOTIFY = "0000fff7-0000-1000-8000-00805f9b34fb"
WRITE = "0000fff6-0000-1000-8000-00805f9b34fb"

GEAR_BITS = {0: "1", 1: "2", 2: "3", 3: "3"}


def bits(b):
    return "".join(str((b >> i) & 1) for i in range(8))


def decode(d):
    h = d.hex(" ")
    if len(d) < 2 or d[0] != 0xAA:
        return f"RAW {h}"
    t = d[1]
    if t == 0x55:
        speed = ((d[3] << 8) | d[2]) / 10.0
        total = d[4] | (d[5] << 8)
        cur = d[6] | (d[7] << 8)
        b9, b10, b11 = bits(d[9]), bits(d[10]), bits(d[11])
        gear = 3 if b11[0:2] == "11" else (2 if b11[0:2] == "01" else 1)
        return (
            f"STATUS  speed={speed} km/h  odo={total} ({total/100:.2f} km)  trip={cur/100:.2f} km  "
            f"batt={d[8]}%  gear={gear}  cruise={b10[1]} start_mode={b11[3]} light={b11[4]}/{b11[5]} "
            f"unit={'MPH' if b11[6] == '1' else 'KM/H'} lock={b11[7]} cycling={b10[3]} thirdgear={b10[5]} "
            f"faults={b9} | {h}"
        )
    if t == 0x56:
        b2 = bits(d[2])
        return (
            f"GEARCFG g1={d[5]} g2={d[6]} g3={d[7]} start={d[8]} km/h  "
            f"ped={b2[0]} bits={b2} | {h}"
        )
    if t == 0x57:
        return (
            f"LIMITS  g1={d[8]}..{d[9]}  g2={d[10]}..{d[11]}  g3={d[12]}..{d[13]} km/h | {h}"
        )
    return f"TYPE {t:02x} {h}"


def cmd_one_two(g1, g2):
    f = bytes([0xAA, 0xCC, 0xA7, g1 & 0xFF, g2 & 0xFF])
    x = f[3] ^ 0xA7
    s = (f[3] + 0xA7 + x) & 0xFF
    return f + bytes([x, s, 0xEE])


def cmd_three(g3, start):
    f = bytes([0xAA, 0xCC, 0xA8, g3 & 0xFF, start & 0xFF])
    x = f[3] ^ 0xA8
    s = (f[3] + 0xA8 + x) & 0xFF
    return f + bytes([x, s, 0xEE])


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secs", type=float, default=20)
    ap.add_argument("--send", default=None, help="hex bytes to write to fff6")
    ap.add_argument("--one-two", default=None, help="g1,g2")
    ap.add_argument("--three", default=None, help="g3,start")
    args = ap.parse_args()

    dev = await BleakScanner.find_device_by_address(ADDR, timeout=20.0)
    if not dev:
        print("not found")
        return
    frames = {}
    t0 = time.time()

    def cb(_h, data):
        d = bytes(data)
        txt = decode(d)
        key = d.hex()
        frames[key] = frames.get(key, 0) + 1
        if frames[key] <= 3:
            print(f"[{time.time()-t0:6.2f}s] {txt}")

    async with BleakClient(dev, timeout=20.0) as c:
        print("connected")
        await c.start_notify(NOTIFY, cb)
        print("subscribed")
        payloads = []
        if args.send:
            payloads.append(bytes.fromhex(args.send.replace(" ", "")))
        if args.one_two:
            a, b = (int(x) for x in args.one_two.split(","))
            payloads.append(cmd_one_two(a, b))
        if args.three:
            a, b = (int(x) for x in args.three.split(","))
            payloads.append(cmd_three(a, b))
        for p in payloads:
            print(f"--> TX {p.hex(' ')}")
            await c.write_gatt_char(WRITE, p, response=False)
            await asyncio.sleep(1.0)
        await asyncio.sleep(args.secs)
        print("\n=== unique frames ===")
        for k, n in sorted(frames.items(), key=lambda kv: -kv[1]):
            print(f"{n:5d}x  {decode(bytes.fromhex(k))}")

asyncio.run(main())
