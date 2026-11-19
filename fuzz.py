import asyncio, argparse, time, os
from bleak import BleakClient, BleakScanner

ADDR = os.environ.get("SCOOTER_MAC", "AA:BB:CC:DD:EE:FF")
NOTIFY = "0000fff7-0000-1000-8000-00805f9b34fb"
WRITE = "0000fff6-0000-1000-8000-00805f9b34fb"

KNOWN = {0x55, 0x56, 0x57}


def frame(sig, d1, d2):
    body = [0xAA, 0xCC, sig, d1 & 0xFF, d2 & 0xFF]
    x = body[3] ^ sig
    s = (body[3] + sig + x) & 0xFF
    return bytes(body + [x, s, 0xEE])


def decode_short(d):
    if len(d) < 2 or d[0] != 0xAA:
        return d.hex(" ")
    t = d[1]
    if t == 0x55:
        return f"STATUS spd={(d[3]<<8)|d[2]} batt={d[8]} gear={d[11]:02x}"
    if t == 0x56:
        return f"GEARCFG {d[5]}/{d[6]}/{d[7]} start={d[8]} raw={d.hex(' ')}"
    if t == 0x57:
        return f"LIMITS {d[8]}-{d[9]}/{d[10]}-{d[11]}/{d[12]}-{d[13]} raw={d.hex(' ')}"
    return f"TYPE {t:02x} {d.hex(' ')}"


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lo", type=lambda x: int(x, 0), default=0xA0)
    ap.add_argument("--hi", type=lambda x: int(x, 0), default=0xBF)
    ap.add_argument("--d1", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--d2", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--gap", type=float, default=0.7)
    args = ap.parse_args()

    dev = await BleakScanner.find_device_by_address(ADDR, timeout=20.0)
    if not dev:
        print("not found")
        return

    window = []
    cur_sig = [None]

    def cb(_h, data):
        window.append((cur_sig[0], bytes(data)))

    async with BleakClient(dev, timeout=20.0) as c:
        await c.start_notify(NOTIFY, cb)
        await asyncio.sleep(2.5)

        base = {}
        for _sig, d in window:
            if len(d) > 1 and d[0] == 0xAA:
                base.setdefault(d[1], set()).add(d.hex())
        print("baseline frame types:", sorted(f"0x{k:02x}" for k in base))
        for k in sorted(base):
            if k not in KNOWN:
                for h in base[k]:
                    print(f"  baseline extra 0x{k:02x}: {h}")

        for sig in range(args.lo, args.hi + 1):
            window.clear()
            cur_sig[0] = sig
            await c.write_gatt_char(WRITE, frame(sig, args.d1, args.d2), response=False)
            await asyncio.sleep(args.gap)
            hits = []
            for s, d in window:
                if s != sig or len(d) < 2 or d[0] != 0xAA:
                    continue
                t = d[1]
                if t == 0x55:
                    continue
                if t in KNOWN:
                    if d.hex() not in base.get(t, set()):
                        hits.append(("CHANGED", d))
                else:
                    hits.append(("NEWTYPE", d))
            if hits:
                print(f"sig 0x{sig:02x}:")
                for kind, d in hits:
                    print(f"   {kind}: {decode_short(d)}")
        print("done")

asyncio.run(main())
