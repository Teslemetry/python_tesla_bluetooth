# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: common.proto
"""Generated protocol buffer code."""

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0c\x63ommon.proto\x12\tCarServer"\x06\n\x04Void".\n\x07LatLong\x12\x10\n\x08latitude\x18\x01 \x01(\x02\x12\x11\n\tlongitude\x18\x02 \x01(\x02"i\n\x14PreconditioningTimes\x12#\n\x08\x61ll_week\x18\x01 \x01(\x0b\x32\x0f.CarServer.VoidH\x00\x12#\n\x08weekdays\x18\x02 \x01(\x0b\x32\x0f.CarServer.VoidH\x00\x42\x07\n\x05times"i\n\x14OffPeakChargingTimes\x12#\n\x08\x61ll_week\x18\x01 \x01(\x0b\x32\x0f.CarServer.VoidH\x00\x12#\n\x08weekdays\x18\x02 \x01(\x0b\x32\x0f.CarServer.VoidH\x00\x42\x07\n\x05times*\x16\n\x07Invalid\x12\x0b\n\x07INVALID\x10\x00\x42n\n$com.tesla.generated.carserver.commonZFgithub.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserverb\x06proto3'
)

_INVALID = DESCRIPTOR.enum_types_by_name["Invalid"]
Invalid = enum_type_wrapper.EnumTypeWrapper(_INVALID)
INVALID = 0


_VOID = DESCRIPTOR.message_types_by_name["Void"]
_LATLONG = DESCRIPTOR.message_types_by_name["LatLong"]
_PRECONDITIONINGTIMES = DESCRIPTOR.message_types_by_name["PreconditioningTimes"]
_OFFPEAKCHARGINGTIMES = DESCRIPTOR.message_types_by_name["OffPeakChargingTimes"]
Void = _reflection.GeneratedProtocolMessageType(
    "Void",
    (_message.Message,),
    {
        "DESCRIPTOR": _VOID,
        "__module__": "common_pb2",
        # @@protoc_insertion_point(class_scope:CarServer.Void)
    },
)
_sym_db.RegisterMessage(Void)

LatLong = _reflection.GeneratedProtocolMessageType(
    "LatLong",
    (_message.Message,),
    {
        "DESCRIPTOR": _LATLONG,
        "__module__": "common_pb2",
        # @@protoc_insertion_point(class_scope:CarServer.LatLong)
    },
)
_sym_db.RegisterMessage(LatLong)

PreconditioningTimes = _reflection.GeneratedProtocolMessageType(
    "PreconditioningTimes",
    (_message.Message,),
    {
        "DESCRIPTOR": _PRECONDITIONINGTIMES,
        "__module__": "common_pb2",
        # @@protoc_insertion_point(class_scope:CarServer.PreconditioningTimes)
    },
)
_sym_db.RegisterMessage(PreconditioningTimes)

OffPeakChargingTimes = _reflection.GeneratedProtocolMessageType(
    "OffPeakChargingTimes",
    (_message.Message,),
    {
        "DESCRIPTOR": _OFFPEAKCHARGINGTIMES,
        "__module__": "common_pb2",
        # @@protoc_insertion_point(class_scope:CarServer.OffPeakChargingTimes)
    },
)
_sym_db.RegisterMessage(OffPeakChargingTimes)

if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    DESCRIPTOR._serialized_options = b"\n$com.tesla.generated.carserver.commonZFgithub.com/teslamotors/vehicle-command/pkg/protocol/protobuf/carserver"
    _INVALID._serialized_start = 297
    _INVALID._serialized_end = 319
    _VOID._serialized_start = 27
    _VOID._serialized_end = 33
    _LATLONG._serialized_start = 35
    _LATLONG._serialized_end = 81
    _PRECONDITIONINGTIMES._serialized_start = 83
    _PRECONDITIONINGTIMES._serialized_end = 188
    _OFFPEAKCHARGINGTIMES._serialized_start = 190
    _OFFPEAKCHARGINGTIMES._serialized_end = 295
# @@protoc_insertion_point(module_scope)
