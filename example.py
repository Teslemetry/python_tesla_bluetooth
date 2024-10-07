from tesla_bluetooth import Vehicle, private_key, valid_name
import asyncio
import bleak


async def main():
    key = await private_key()

    print("Scanning for vehicles...")
    devices = [
        device
        for device in await bleak.BleakScanner().discover()
        if valid_name(device.name)
    ]
    if len(devices) == 1:
        choice = 0
    else:
        # list choices and prompt user to select one
        print("Please select a vehicle:")
        for i, device in enumerate(devices):
            print(f"{i}: {device.name} [{device.address}]")
        choice = int(input("Enter choice: "))

    async with Vehicle(devices[choice], key) as vehicle:
        vehicle.debug()

        #await vehicle.authenticationRequest()

        if not vehicle.isAdded():
            print("Tap your keycard on the center console")
            await vehicle.whitelist()

        # Print closure status of all doors when they change
        vehicle.onStatusChange( #set_notify
            lambda vehic: print(f"\nStatus update: {vehic.status()}\n")
        )

        # Request status
        await vehicle.vehicle_status()

        command = ""
        while True:
            print(
                "Enter a command, or 'help' for a list of commands. Type 'exit' to quit."
            )
            command = input("Enter command: ")
            command = command.upper().replace(" ", "_")
            if command == "LOCK":
                vehicle.lock()
            elif command == "UNLOCK":
                vehicle.unlock()
            elif command == "OPEN_TRUNK":
                vehicle.open_trunk()
            elif command == "OPEN_FRUNK":
                vehicle.open_frunk()
            elif command == "OPEN_CHARGE_PORT":
                vehicle.open_charge_port()
            elif command == "CLOSE_CHARGE_PORT":
                vehicle.close_charge_port()
            elif command == "EXIT":
                break
            elif command == "HELP":
                print("\n\n\nCommands available:")
                print("\tEXIT: Exit the program")
                print("\tHELP: Print this message")
                print("\tLOCK: Lock the vehicle")
                print("\tUNLOCK: Unlock the vehicle")
                print("\tOPEN_TRUNK: Open the vehicle's trunk")
                print("\tOPEN_FRUNK: Open the vehicle's front trunk")
                print("\tOPEN_CHARGE_PORT: Open and unlock the vehicle's charge port")
                print("\tCLOSE_CHARGE_PORT: Close and lock the vehicle's charge port")
                print("\n\n")
            else:
                print("Unknown command")
        print("Disconnecting...")


asyncio.run(main())
