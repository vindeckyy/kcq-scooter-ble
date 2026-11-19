import asyncio, sys, time, os
from bleak import BleakClient, BleakScanner

ADDR = os.environ.get("SCOOTER_MAC", "AA:BB:CC:DD:EE:FF")
NOTIFY = "0000fff7-0000-1000-8000-00805f9b34fb"


def bits(b):
    return "".join(str((b >> i) & 1) for i in range(8))


async def main():
    dev = await BleakScanner.find_device_by_address(ADDR, timeout=20.0)
    if not dev:
        print("not found")
        return
    peak = 0
    seen = {}
    last_print = 0.0
    t0 = time.time()

    def cb(_h, data):
        nonlocal peak, last_print
        d = bytes(data)
        if len(d) < 2 or d[0] != 0xAA:
            return
        if d[1] == 0x55:
            raw = (d[3] << 8) | d[2]
            speed = raw / 10.0
            peak = max(peak, raw)
            now = time.time()
            if now - last_print >= 1.0:
                last_print = now
                print(
                    f"[{now-t0:6.1f}s] speed={speed:5.1f} km/h ({speed/1.6:4.1f} mph)  "
                    f"peak={peak/10:5.1f} km/h ({peak/16:4.1f} mph)  batt={d[8]}%  "
                    f"odo={(d[4]|(d[5]<<8))/100:.2f}km  gearbits={bits(d[11])[:2]}",
                    flush=True,
                )
        else:
            k = d.hex()
            seen[k] = seen.get(k, 0) + 1

    async with BleakClient(dev, timeout=20.0) as c:
        await c.start_notify(NOTIFY, cb)
        print("connected - logging. Ride now. Ctrl-C to stop.", flush=True)
        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            print(f"\nPEAK SPEED: {peak} km/h = {peak/1.6:.1f} mph")
            for k, n in seen.items():
                print(f"  {n}x {k}")


try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
