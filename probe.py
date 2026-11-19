import asyncio, sys, time, os
from bleak import BleakClient, BleakScanner

ADDR = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SCOOTER_MAC", "AA:BB:CC:DD:EE:FF")
CAPTURE_SECS = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0

def hexs(b):
    return " ".join(f"{x:02x}" for x in b)

async def main():
    dev = await BleakScanner.find_device_by_address(ADDR, timeout=20.0)
    if dev is None:
        print("device not found")
        return
    print(f"found {dev.name} {dev.address}")
    async with BleakClient(dev, timeout=20.0) as c:
        print("connected:", c.is_connected)
        print("\n=== GATT ===")
        chars = []
        for svc in c.services:
            print(f"\nservice {svc.uuid}  handle={svc.handle}")
            for ch in svc.characteristics:
                print(f"  char {ch.uuid}  handle={ch.handle}  props={','.join(ch.properties)}")
                chars.append(ch)

        print("\n=== READS ===")
        for ch in chars:
            if "read" in ch.properties:
                try:
                    v = await c.read_gatt_char(ch)
                    print(f"  {ch.uuid} -> {hexs(v)}")
                except Exception as e:
                    print(f"  {ch.uuid} -> ERR {e}")

        events = []
        def mk(uuid):
            def cb(_h, data):
                events.append((time.time(), uuid, bytes(data)))
                print(f"  [{uuid}] {hexs(data)}")
            return cb

        print(f"\n=== NOTIFY ({CAPTURE_SECS}s) ===")
        subs = []
        for ch in chars:
            if "notify" in ch.properties or "indicate" in ch.properties:
                try:
                    await c.start_notify(ch, mk(str(ch.uuid)[4:8]))
                    subs.append(ch)
                    print(f"  subscribed {ch.uuid}")
                except Exception as e:
                    print(f"  subscribe {ch.uuid} ERR {e}")
        await asyncio.sleep(CAPTURE_SECS)
        for ch in subs:
            try:
                await c.stop_notify(ch)
            except Exception:
                pass
        print(f"\ncaptured {len(events)} notifications")

asyncio.run(main())
