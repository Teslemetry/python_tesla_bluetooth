# protobuf
import asyncio
import os

from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.service import BleakGATTService
from .pb2 import vcsec_pb2 as vcsec, keys_pb2 as keys

# cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# encoding
import binascii

# ble
import bleak
from aiofiles import open

# regex
import re

# files
from os.path import exists

# time
import time


async def private_key(path="private_key.pem") -> ec.EllipticCurvePrivateKey:
    """Create or load the private key."""
    if not exists(path):
        value = ec.generate_private_key(ec.SECP256R1(), default_backend())
        # save the key
        pem = value.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        async with open(path, "wb") as key_file:
            await key_file.write(pem)
        return value
    else:
        try:
            async with open(path, "rb") as key_file:
                key_data = await key_file.read()
                value = serialization.load_pem_private_key(
                    key_data, password=None, backend=default_backend()
                )
            assert isinstance(value, ec.EllipticCurvePrivateKey)
            return value
        except Exception as e:
            print(e)
            exit()


def valid_name(name) -> bool:
    """Check if a BLE device name is a valid Tesla vehicle."""
    return bool(re.match("^S[a-f0-9]{16}[A-F]$", name))


class Vehicle:
    __service: BleakGATTService

    def __init__(self, device: BLEDevice, private_key: ec.EllipticCurvePrivateKey):
        self.__device = device
        self.__client = bleak.BleakClient(device)
        self.__private_key = private_key
        self.__vehicle_key_str = ""
        self.__counter = int(time.time())
        self.__msg = TeslaMsgService(self)
        self.__debug = False

    def __str__(self):
        return f"{self.name()} ({self.address()})"

    def debug(self):
        self.__debug = True

    def onStatusChange(self, func):
        self.__onStatusChange = func

    def setStatus(self, data):
        closure_status = data.closureStatuses
        lock_state = data.vehicleLockState
        print(lock_state)
        self.__locked = lock_state == 1
        self.__charge_port_open = closure_status.chargePort == 1
        self.__front_driver_door_open = closure_status.frontDriverDoor == 1
        self.__rear_driver_door_open = closure_status.rearDriverDoor == 1
        self.__front_passenger_door_open = closure_status.frontPassengerDoor == 1
        self.__rear_passenger_door_open = closure_status.rearPassengerDoor == 1
        self.__rear_trunk_open = closure_status.rearTrunk == 1
        self.__front_trunk_open = closure_status.frontTrunk == 1
        if self.__onStatusChange is not None:
            self.__onStatusChange(self)

    def status(self):
        return {
            "locked": self.__locked,
            "charge_port_open": self.__charge_port_open,
            "front_driver_door_open": self.__front_driver_door_open,
            "rear_driver_door_open": self.__rear_driver_door_open,
            "front_passenger_door_open": self.__front_passenger_door_open,
            "rear_passenger_door_open": self.__rear_passenger_door_open,
            "rear_trunk_open": self.__rear_trunk_open,
            "front_trunk_open": self.__front_trunk_open,
        }

    def is_debug(self):
        return self.__debug

    def updateFile(self):
        pass

    def address(self):
        return self.__device.address

    def name(self):
        return self.__device.name

    def counter(self):
        return self.__counter

    def setCounter(self, counter):
        self.__counter = counter

    def private_key(self):
        return self.__private_key

    def vehicle_key_str(self):
        if self.__vehicle_key_str == "null" or len(self.__vehicle_key_str) < 10:
            return None
        return self.__vehicle_key_str

    def setVehicleKeyStr(self, vehicle_key):
        self.__vehicle_key_str = vehicle_key
        self.updateFile()

    async def connect(self):
        await self.__client.connect()
        print("Connected to", self.name())

    async def __aenter__(self):
        await self.connect()
        return self

    async def disconnect(self):
        await self.__client.disconnect()

    async def __aexit__(self, exc_type, exc, tb):
        await self.disconnect()

    async def check_key(self):
        msg = self.__msg.informationRequestMsg()
        await self.write(msg)


    async def listen(self):
        await self.__client.start_notify(TeslaUUIDs.CHAR_READ_UUID, self.__msg.handle_notify)
        print("Listening for notifications...")

    async def whitelist(self):

        info = await self.read_write(self.__msg.whitelistMsg(),"informationRequest")
        print(info)

        info = await self.read_write(self.__msg.whitelistEntryMsg(),"informationRequest")
        print(info)

        info = await self.read_write(self.__msg.whitelistEntryInfoMsg(),"informationRequest")
        print(info)

        print("Sent whitelist request")

        while not self.isAdded():
            msg = await self.read_write(self.__msg.whitelistMsg(),"commandStatus")
            print(msg)

    async def unlock(self):
        msg = self.__msg.unlockMsg()
        await self.write(bytes(msg))

    async def lock(self):
        msg = self.__msg.lockMsg()
        await self.write(bytes(msg))

    async def open_trunk(self):
        msg = self.__msg.openTrunkMsg()
        await self.write(bytes(msg))

    async def open_frunk(self):
        msg = self.__msg.openFrunkMsg()
        await self.write(bytes(msg))

    async def open_charge_port(self):
        msg = self.__msg.openChargePortMsg()
        await self.write(bytes(msg))

    async def close_charge_port(self):
        msg = self.__msg.closeChargePortMsg()
        await self.write(bytes(msg))

    async def vehicle_status(self):
        msg = self.__msg.vehicleStatusMsg()
        msg = bytes(msg)
        await self.write(msg)

    async def vehicle_info(self):
        msg = self.__msg.vehicleInfoMsg()
        msg = bytes(msg)
        return await self.write(msg)

    def isAdded(self):
        return self.__msg.isAdded()

    def isConnected(self):
        return self.__client.is_connected

    async def set_notify(self, onNotify):
        await self.__client.start_notify(TeslaUUIDs.CHAR_READ_UUID, onNotify)
        await self.write(bytes([0x01]))

    async def authenticationRequest(self, requested_level):
        msg = self.__msg.authenticationRequestMsg(requested_level)
        msg = bytes(msg)
        await self.write(msg)

    async def write(self, msg):
        return await self.__client.write_gatt_char(TeslaUUIDs.CHAR_WRITE_UUID, msg)

    async def read(self, sub_message: str):
        event = asyncio.Event()

        def callback(characteristic: BleakGATTCharacteristic, data: bytearray):
            nonlocal event
            msg = vcsec.FromVCSECMessage()
            msg.ParseFromString(data[2:])
            if msg.WhichOneof("sub_message") == sub_message:
                event.set()
                return msg[sub_message]
            else:
                print("Discarding: ", msg)

        await self.__client.start_notify(TeslaUUIDs.CHAR_READ_UUID, callback)

        try:
            await asyncio.wait_for(event.wait(), timeout=10)
        except asyncio.TimeoutError:
            print(f"Timeout waiting for {sub_message}")
            return None
        finally:
            await self.__client.stop_notify(TeslaUUIDs.CHAR_READ_UUID)

    async def read_write(self, msg, sub_message: str):
        event = asyncio.Event()

        def callback(characteristic: BleakGATTCharacteristic, data: bytearray):
            nonlocal event
            msg = vcsec.FromVCSECMessage()
            msg.ParseFromString(data[2:])
            if(msg):
                print(msg)
            if msg.WhichOneof("sub_message") == sub_message:
                event.set()
                return getattr(msg, sub_message)
            elif msg.WhichOneof("sub_message") == "commandStatus":
                event.set()
                raise Exception(getattr(msg, "commandStatus"))

        await self.__client.start_notify(TeslaUUIDs.CHAR_READ_UUID, callback)
        await self.__client.write_gatt_char(TeslaUUIDs.CHAR_WRITE_UUID, bytes(msg))

        try:
            await asyncio.wait_for(event.wait(), timeout=10)
        except asyncio.TimeoutError:
            print(f"Timeout waiting for {sub_message}")
            return None
        finally:
            await self.__client.stop_notify(TeslaUUIDs.CHAR_READ_UUID)


class TeslaMsgService:
    def __init__(self, vehicle):
        self.__vehicle = vehicle
        self.setCounter(vehicle.counter())
        self.vehicle_key = None
        self.private_key = vehicle.private_key()
        vehicle_key_str = vehicle.vehicle_key_str()
        if vehicle_key_str is not None:
            self.loadEphemeralKey(vehicle_key_str)

    def __str__(self):
        return "BLE Address: {}, Name: {}".format(
            self.__vehicle.address(), self.__vehicle.name()
        )

    def vehicle(self):
        return self.__vehicle

    def isAdded(self):
        return self.vehicle_key != None

    def getPrivateKey(self):
        private_key_bytes = self.__vehicle.private_key().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_key_bytes

    def getPublicKey(self):
        public_key_bytes = (
            self.__vehicle.private_key()
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        )
        return public_key_bytes

    def getKeyId(self):
        public_key = self.getPublicKey()

        digest = hashes.Hash(hashes.SHA1())
        digest.update(public_key)
        return digest.finalize()[:4]

    def getSharedKey(self):
        # creates sha1 hasher for creating shared key
        hasher = hashes.Hash(hashes.SHA1())
        # exchange own private key with car's ephemeral key to create an intermediate shared key
        shared_key = self.private_key.exchange(ec.ECDH(), self.vehicle_key)
        # intermediate shared key is then inserted into the hasher
        hasher.update(shared_key)
        # and the first 16 bytes of the hash will be our final shared key
        return hasher.finalize()[:16]

    def signedToMsg(self, message):
        if not self.isAdded():
            raise Exception("Car's ephermeral key not yet loaded!")
        shared_secret = self.getSharedKey()
        encryptor = AESGCM(shared_secret)
        nonce = bytearray()
        nonce.append((self.counter >> 24) & 255)
        nonce.append((self.counter >> 16) & 255)
        nonce.append((self.counter >> 8) & 255)
        nonce.append(self.counter & 255)

        umsg_to = vcsec.ToVCSECMessage()
        umsg_to.unsignedMessage.CopyFrom(message)

        encrypted_msg = encryptor.encrypt(nonce, umsg_to.SerializeToString(), None)

        msg = vcsec.ToVCSECMessage()
        signed_msg = msg.signedMessage
        signed_msg.protobufMessageAsBytes = encrypted_msg[:-16]
        signed_msg.signatureType = vcsec.SIGNATURE_TYPE_AES_GCM
        signed_msg.counter = self.counter
        signed_msg.signature = encrypted_msg[-16:]
        signed_msg.keyId = self.getKeyId()

        self.setCounter(self.counter + 1)
        return self.prependLength(msg.SerializeToString())

    def unsignedToMsg(self, message):
        msg = vcsec.UnsignedMessage()
        msg.CopyFrom(message)
        return self.prependLength(msg.SerializeToString())

    def prependLength(self, message):
        return bytearray([len(message) >> 8, len(message) & 0xFF]) + message

    def loadEphemeralKey(self, key):
        if isinstance(key, str):
            key = key[2:-1]
            key = binascii.unhexlify(key)
        self.ephemeral_str = binascii.hexlify(key)
        curve = ec.SECP256R1()
        self.vehicle_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, key)
        self.__vehicle.setVehicleKeyStr(self.ephemeral_str)

    def setCounter(self, counter):
        self.counter = counter
        self.__vehicle.setCounter(counter)

    ###########################       PROCESS RESPONSES       #############################

    def handle_notify(self, characteristic: BleakGATTCharacteristic, data: bytearray):
        # remove first two bytes (length)
        data = data[2:]
        msg = vcsec.FromVCSECMessage()
        msg.ParseFromString(data)
        print("message", msg)


        # see if the response is the shared key
        if msg.WhichOneof("sub_message") == "whitelistInfo":
            print("whitelistInfo", msg.whitelistInfo.whitelistEntries)
            id = self.getKeyId()
            for publicKey in msg.whitelistInfo.whitelistEntries:
                print("whitelistEntry", publicKey.publicKeySHA1, id, publicKey.publicKeySHA1 == id)
                if(publicKey.publicKeySHA1 == id):
                    print("Found it!")
                    self.vehicle_key = id
                    return

        elif msg.WhichOneof("sub_message") == "whitelistEntryInfo":
            key = msg.whitelistEntryInfo.publicKey
            self.loadEphemeralKey(key)
            print("Loaded ephemeral key", key)
        #elif msg.HasField("authenticationRequest"):
            #self.__vehicle.authenticationRequest(
            #    msg.authenticationRequest.requestedLevel
            #)
        elif msg.WhichOneof("sub_message") == "vehicleStatus":
            self.__vehicle.setStatus(msg.vehicleStatus)
        elif msg.WhichOneof("sub_message") == "commandStatus":
            print("commandStatus")
        elif msg.WhichOneof("sub_message") == "nominalError":
            print("Nominal Error:", msg.nominalError)
        else:
            pass

        # TODO: check if the message is signed
        # TODO: get command status
        # TODO: do something with the message
        return True

    ###########################       VEHICLE ACTIONS       #############################

    # These functions generate a message to perform a particular action, such
    # as unlocking the vehicle. The response is in the form of a byte array.
    # Note: It still needs to be encrypted and prepended.

    def whitelistMsg(self):
        # request to add a vehicle to the whitelist, request permissions
        msg = vcsec.UnsignedMessage()
        whitelist_operation = msg.WhitelistOperation
        permissions_action = whitelist_operation.addKeyToWhitelistAndAddPermissions
        permissions_action.key.PublicKeyRaw = self.getPublicKey()
        permissions_action.keyRole = keys.ROLE_OWNER
        # permissions.append(vcsec.WHITELISTKEYPERMISSION_LOCAL_DRIVE)
        # permissions.append(vcsec.WHITELISTKEYPERMISSION_LOCAL_UNLOCK)
        # permissions.append(vcsec.WHITELISTKEYPERMISSION_REMOTE_DRIVE)
        # permissions.append(vcsec.WHITELISTKEYPERMISSION_REMOTE_UNLOCK)
        whitelist_operation.metadataForKey.keyFormFactor = (
            vcsec.KEY_FORM_FACTOR_ANDROID_DEVICE
        )

        msg2 = vcsec.ToVCSECMessage()
        msg2.signedMessage.signatureType = vcsec.SIGNATURE_TYPE_PRESENT_KEY
        msg2.signedMessage.protobufMessageAsBytes = msg.SerializeToString()
        return self.prependLength(msg2.SerializeToString())

    def unlockMsg(self):
        # unlocks the vehicle
        return self.rkeActionMsg(vcsec.RKEAction_E.RKE_ACTION_UNLOCK)

    def lockMsg(self):
        return self.rkeActionMsg(vcsec.RKEAction_E.RKE_ACTION_LOCK)

    def openTrunkMsg(self):
        # opens the rear trunk
        return self.rkeActionMsg(vcsec.RKEAction_E.RKE_ACTION_OPEN_TRUNK)

    def openFrunkMsg(self):
        # opens the front trunk
        return self.rkeActionMsg(vcsec.RKEAction_E.RKE_ACTION_OPEN_FRUNK)

    def openChargePortMsg(self):
        # opens the charge port
        return self.rkeActionMsg(vcsec.RKEAction_E.RKE_ACTION_OPEN_CHARGE_PORT)

    def closeChargePortMsg(self):
        # closes the charge port
        return self.rkeActionMsg(vcsec.RKEAction_E.RKE_ACTION_CLOSE_CHARGE_PORT)

    def rkeActionMsg(self, action):
        # executes the given RKE action
        msg = vcsec.UnsignedMessage()
        msg.RKEAction = action
        return self.signedToMsg(msg)

    def informationRequestMsg(self, type):
        # requests information about the vehicle
        msg = vcsec.UnsignedMessage()
        info_request = msg.InformationRequest
        info_request.informationRequestType = type
        info_request.publicKey = self.getPublicKey()
        #info_request.keyId = self.getKeyId()
        return self.unsignedToMsg(msg)
        #return self.signedToMsg(msg)

    def whitelistEntryMsg(self):
        return self.informationRequestMsg(
            vcsec.INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO
        )

    def whitelistEntryInfoMsg(self):
        return self.informationRequestMsg(
            vcsec.INFORMATION_REQUEST_TYPE_GET_WHITELIST_ENTRY_INFO
        )

    def vehicleStatusMsg(self):
        return self.informationRequestMsg(vcsec.INFORMATION_REQUEST_TYPE_GET_STATUS)

    def authenticationRequestMsg(self, level):
        msg = vcsec.UnsignedMessage()
        msg.authenticationResponse.authenticationLevel = level
        return self.signedToMsg(msg)

    def vehiclePublicKeyMsg(self):
        # requests the public key of the vehicle
        msg = vcsec.UnsignedMessage()
        info_request = msg.InformationRequest
        info_request.informationRequestType = (
            vcsec.INFORMATION_REQUEST_TYPE_GET_EPHEMERAL_PUBLIC_KEY
        )
        key_id = info_request.keyId
        key_id.publicKeySHA1 = self.getKeyId()
        return self.unsignedToMsg(msg)


class TeslaUUIDs:
    SERVICE_UUID = "00000211-b2d1-43f0-9b88-960cebf8b91e"  # Tesla Vehicle Service
    CHAR_WRITE_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e"  # To Vehicle
    CHAR_READ_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e"  # From Vehicle
    CHAR_VERSION_UUID = "00000214-b2d1-43f0-9b88-960cebf8b91e"  # Version Info
