# protobuf
import VCSEC_pb2
# cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, asymmetric, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
# json
import json


class TeslaUUIDs:
    SERVICE_UUID = "00000211-b2d1-43f0-9b88-960cebf8b91e"       # Tesla Vehicle Service
    CHAR_WRITE_UUID = "00000212-b2d1-43f0-9b88-960cebf8b91e"    # To Vehicle
    CHAR_READ_UUID = "00000213-b2d1-43f0-9b88-960cebf8b91e"     # From Vehicle
    CHAR_VERSION_UUID = "00000214-b2d1-43f0-9b88-960cebf8b91e"  # Version Info


class TeslaVehicle:
    def __init__(self, ble_address, name, vehicle_eph_public_key=None):
        self.ble_address = ble_address
        self.ble_name = name
        self.vehicle_eph_public_key = vehicle_eph_public_key
        self.generate_keys()
        self.counter = 0

    def __str__(self):
        return "BLE Address: {}, Name: {}".format(self.ble_address, self.ble_name)
    
    def isInitialized(self):
        return len(self.vehicle_eph_public_key) > 10

    def getPrivateKey(self):
        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_bytes

    def getPublicKey(self):
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_bytes

    def generate_keys(self):
        # checks for a file named private_key.pem
        # if it exists, load the key
        # else generate a new key
        try:
            with open("private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except FileNotFoundError:
            # generate a new key
            private_key = ec.generate_private_key(
                ec.SECP256R1(), default_backend())
            # save the key
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open("private_key.pem", 'wb') as pem_out:
                pem_out.write(pem)
            print("Generated private key")
        self.private_key = private_key
        self.public_key = private_key.public_key()

    def signedToMsg(self, message):
        shared_secret = self.getPublicKey()
        encryptor = AESGCM(shared_secret)
        nonce = bytearray()
        nonce.append((self.counter >> 24) & 255)
        nonce.append((self.counter >> 16) & 255)
        nonce.append((self.counter >> 8) & 255)
        nonce.append(self.counter & 255)

        encrypted_msg = encryptor.encrypt(
            nonce,
            message,
            None
        )

        # keyID is SHA1 of the public key
        key_id = hashes.Hash(hashes.SHA1(), backend=default_backend())

        msg = VCSEC_pb2.ToVCSECMessage()
        signed_msg = msg.signedMessage
        signed_msg.protobufMessageAsBytes = encrypted_msg[:-16]
        signed_msg.signatureType = VCSEC_pb2.SIGNATURE_TYPE_PRESENT_KEY
        signed_msg.counter = self.counter
        signed_msg.signature = encrypted_msg[-16:]
        signed_msg.keyId = key_id.update(shared_secret).finalize()
        return self.prependLength(msg.SerializeToString())
    
    def unsignedToMsg(self, message):
        msg = VCSEC_pb2.ToVCSECMessage()
        unsigned_msg = msg.signedMessage
        unsigned_msg.protobufMessageAsBytes = message
        unsigned_msg.signatureType = VCSEC_pb2.SIGNATURE_TYPE_PRESENT_KEY
        return self.prependLength(msg.SerializeToString())

    def prependLength(self, message):
        # Extends the length of the byte array by two
        # Shifts all bytes to the right by two
        # Sets the first two bytes to the length of the message
        return bytearray([len(message) >> 8, len(message) & 0xFF]) + message

    ###########################       PROCESS RESPONSES       #############################
    # FromVCSECMessage {
    #     commandStatus {
    #         operationStatus: OPERATIONSTATUS_WAIT
    #     }
    # }
    def handle_notify(self, sender, data):
        # remove first two bytes (length)
        data = data[2:]
        msg = VCSEC_pb2.FromVCSECMessage()
        msg.ParseFromString(data)
        print(msg)
        # TODO: check if the message is signed
        # TODO: get command status
        # TODO: do something with the message
        return 0

    ###########################       VEHICLE ACTIONS       #############################

    # These functions generate a message to perform a particular action, such
    # as unlocking the vehicle. The response is in the form of a byte array.
    # Note: It still needs to be encrypted and prepended.

    def whitelistOp(self):
        # request to add a vehicle to the whitelist, request permissions
        msg = VCSEC_pb2.UnsignedMessage()
        whitelist_operation = msg.WhitelistOperation
        permissions_action = whitelist_operation.addKeyToWhitelistAndAddPermissions
        permissions_action.key.PublicKeyRaw = self.getPublicKey()
        permissions = permissions_action.permission
        permissions.append(VCSEC_pb2.WHITELISTKEYPERMISSION_LOCAL_DRIVE)
        permissions.append(VCSEC_pb2.WHITELISTKEYPERMISSION_LOCAL_UNLOCK)
        permissions.append(VCSEC_pb2.WHITELISTKEYPERMISSION_REMOTE_DRIVE)
        permissions.append(VCSEC_pb2.WHITELISTKEYPERMISSION_REMOTE_UNLOCK)
        # permissions_action.metadataForKey.keyFormFactor = VCSEC_pb2.KEY_FORM_FACTOR_ANDROID_DEVICE
        return self.unsignedToMsg(msg.SerializeToString())

    def unlockMsg(self):
        # unlocks the vehicle
        return self.rkeActionMsg(VCSEC_pb2.RKEAction_E.RKE_ACTION_UNLOCK)

    def lockMsg(self):
        return self.rkeActionMsg(VCSEC_pb2.RKEAction_E.RKE_ACTION_LOCK)

    def openTrunkMsg(self):
        # opens the rear trunk
        return self.rkeActionMsg(VCSEC_pb2.RKEAction_E.RKE_ACTION_OPEN_TRUNK)

    def rkeActionMsg(self, action):
        # executes the given RKE action
        msg = VCSEC_pb2.UnsignedMessage()
        msg.RKEAction = action
        return self.signedToMsg(msg.SerializeToString())

    def vehiclePublicKeyMsg(self):
        # requests the public key of the vehicle
        msg = VCSEC_pb2.UnsignedMessage()
        info_request = msg.InformationRequest
        info_request.informationRequestType = VCSEC_pb2.INFORMATION_REQUEST_TYPE_GET_EPHEMERAL_PUBLIC_KEY
        key_id = info_request.keyId
        key_id.publicKeySHA1 = self.getPublicKey()
        return self.signedToMsg(msg.SerializeToString())
