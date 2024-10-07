import bleak
import asyncio


async def run():
    devices = await bleak.BleakScanner().discover()
    print(devices)

    for device in devices:
        if len(device.name) == 18 and device.name[0] == "S" and device.name[17] == "C":
            print(device.name)
            async with bleak.BleakClient(device) as client:
                print(client.services)
                print(client.services["00000211-b2d1-43f0-9b88-960cebf8b91e"])
                for service in client.services:
                    print(service)
                    print(
                        service.get_characteristic(
                            "00002A00-0000-1000-8000-00805F9B34FB"
                        )
                    )
                # print(client.read_gatt_char("00002A00-0000-1000-8000-00805F9B34FB"))


loop = asyncio.get_event_loop()
loop.run_until_complete(run())
