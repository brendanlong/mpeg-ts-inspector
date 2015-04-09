from collections import OrderedDict
from itertools import count
import logging
import struct
import zlib

import bitstring
from bitstring import BitArray, BitStream
from common import to_json
import crcmod


crc32 = crcmod.predefined.mkCrcFun("crc-32-mpeg")


def read_ts(file_name):
    with open(file_name, "rb") as f:
        for byte_offset in count(step=TSPacket.SIZE):
            ts_data = f.read(TSPacket.SIZE)
            if not ts_data:
                break
            yield TSPacket.parse(ts_data, byte_offset)


def read_pes(media_segment, initialization_segment=None):
    pmt_pids = set()
    pes_readers = {}
    for segment in initialization_segment, media_segment:
        if not segment:
            continue
        for ts_packet in read_ts(segment):
            if ts_packet.pid == ProgramAssociationTable.PID:
                pat = ProgramAssociationTable(ts_packet.payload)
                pmt_pids.update(pat.programs.values())

            elif ts_packet.pid == pmt_pid:
                pmt = ProgramMapTable(ts_packet.payload)
                for pid in pmt.streams:
                    if pid not in pes_readers:
                        pes_readers[pid] = PESReader()

            elif ts_packet.pid in pes_readers:
                pes_packet = pes_readers[ts_packet.pid].add_ts_packet(ts_packet)
                if pes_packet:
                    yield pes_packet


def read_timestamp(name, data):
    timestamp = data.read("uint:3")
    if not data.read("bool"):
        raise Exception("First marker bit in {} section of header is not "
                        "1.".format(name))
    timestamp = (timestamp << 15) + data.read("uint:15")
    if not data.read("bool"):
        raise Exception("Second marker bit in {} section of header is not "
                        "1.".format(name))
    timestamp = (timestamp << 15) + data.read("uint:15")
    if not data.read("bool"):
        raise Exception("Third marker bit in {} section of header is not "
                        "1.".format(name))
    return timestamp


class TSPacket(object):
    SYNC_BYTE = 0x47
    SIZE = size = 188

    def __init__(self, pid):
        self.transport_error_indicator = False
        self.payload_unit_start_indicator = False
        self.transport_priority = False
        self.pid = pid
        self.scrambling_control = 0
        self.continuity_counter = 0

        self.discontinuity_indicator = False
        self.random_access_indicator = False
        self.elementary_stream_priority_indicator = False

        self.program_clock_reference_base = None
        self.program_clock_reference_extension = None
        self.original_program_clock_reference_base = None
        self.original_program_clock_reference_extension = None
        self.splice_countdown = None
        self.private_data = None
        self.ltw_valid_flag = None
        self.ltw_offset = None
        self.piecewise_rate = None
        self.splice_type = None
        self.dts_next_au = None

    @staticmethod
    def parse(data, byte_offset):
        ts = TSPacket(None)
        ts.byte_offset = byte_offset

        data = BitStream(data)
        sync_byte = data.read("uint:8")
        if sync_byte != TSPacket.SYNC_BYTE:
            raise Exception("First byte of TS packet is not a sync byte.")

        ts.transport_error_indicator = data.read("bool")
        ts.payload_unit_start_indicator = data.read("bool")
        ts.transport_priority = data.read("bool")
        ts.pid = data.read("uint:13")
        ts.scrambling_control = data.read("uint:2")

        # adaptation_field_control
        has_adaptation_field = data.read("bool")
        has_payload = data.read("bool")

        ts.continuity_counter = data.read("uint:4")
        if has_adaptation_field:
            adaptation_field_length = data.read("uint:8")
            if adaptation_field_length:
                ts.discontinuity_indicator = data.read("bool")
                ts.random_access_indicator = data.read("bool")
                ts.elementary_stream_priority_indicator = data.read("bool")
                pcr_flag = data.read("bool")
                opcr_flag = data.read("bool")
                splicing_point_flag = data.read("bool")
                transport_private_data_flag = data.read("bool")
                adaptation_field_extension_flag = data.read("bool")

                if pcr_flag:
                    ts.program_clock_reference_base = data.read("uint:33")
                    data.read(6)  # reserved
                    ts.program_clock_reference_extension = data.read("uint:9")

                if opcr_flag:
                    ts.original_program_clock_reference_base = data.read(
                        "uint:33")
                    data.read(6)  # reserved
                    ts.original_program_clock_reference_extension = data.read(
                        "uint:9")

                if splicing_point_flag:
                    ts.splice_countdown = data.read("uint:8")

                if transport_private_data_flag:
                    transport_private_data_length = data.read("uint:8")
                    ts.private_data = data.read(
                        transport_private_data_length * 8).bytes

                if adaptation_field_extension_flag:
                    adaptation_field_extension_length = data.read("uint:8")
                    ltw_flag = data.read("bool")
                    piecewise_rate_flag = data.read("bool")
                    seamless_splice_flag = data.read("bool")
                    data.read(5)  # reserved

                    if ltw_flag:
                        ts.ltw_valid_flag = data.read("bool")
                        ts.ltw_offset = data.read("uint:15")

                    if piecewise_rate_flag:
                        data.read(2)  # reserved
                        ts.piecewise_rate = data.read("uint:22")

                    if seamless_splice_flag:
                        ts.splice_type = data.read("uint:4")
                        ts.dts_next_au = read_timestamp("DTS_next_AU", data)

                # Skip the rest of the header and padding bytes
                data.bytepos = adaptation_field_length + 5

        if has_payload:
            ts.payload = data.read("bytes")
        return ts

    @property
    def bytes(self):
        adaptation_field_extension_length = 1
        if self.ltw_valid_flag is not None:
            adaptation_field_extension_length += 2
        if self.piecewise_rate is not None:
            adaptation_field_extension_length += 3
        if self.splice_type is not None:
            adaptation_field_extension_length += 5

        # adaptation field stuffing bytes
        if self.payload is not None:
            adaptation_field_length = 188 - len(self.payload) - 5
        else:
            adaptation_field_length = 0
            if self.program_clock_reference_base is not None:
                adaptation_field_length += 6
            if self.original_program_clock_reference_base is not None:
                adaptation_field_length += 6
            if self.splice_countdown is not None:
                adaptation_field_length += 1
            if self.private_data is not None:
                adaptation_field_length += len(self.private_data)
            if adaptation_field_extension_length > 1:
                adaptation_field_length += adaptation_field_extension_length

            if adaptation_field_length > 0:
                adaptation_field_length += 1

        binary = bitstring.pack(
            "uint:8, bool, bool, bool, uint:13, uint:2, bool, bool, uint:4",
            self.SYNC_BYTE, self.transport_error_indicator,
            self.payload_unit_start_indicator, self.transport_priority,
            self.pid, self.scrambling_control, adaptation_field_length >= 0,
            self.payload is not None, self.continuity_counter)

        if adaptation_field_length >= 0:
            binary.append(bitstring.pack(
                "uint:8",
                adaptation_field_length))

            if adaptation_field_length > 0:
                binary.append(bitstring.pack(
                    "bool, bool, bool, bool, bool, bool, bool, bool",
                    self.discontinuity_indicator,
                    self.random_access_indicator,
                    self.elementary_stream_priority_indicator,
                    self.program_clock_reference_base is not None,
                    self.original_program_clock_reference_base is not None,
                    self.splice_countdown is not None,
                    self.private_data is not None,
                    adaptation_field_extension_length > 1))

            if self.program_clock_reference_base is not None:
                binary.append(bitstring.pack(
                    "uint:33, pad:6, uint:9",
                    self.program_clock_reference_base,
                    self.program_clock_reference_extension))

            if self.original_program_clock_reference_base:
                binary.append(bitstring.pack(
                    "uint:33, pad:6, uint:9",
                    self.original_program_clock_reference_base,
                    self.original_program_clock_reference_extension))

            if self.splice_countdown:
                binary.append(bitstring.pack("uint:8", self.splice_coundown))

            if self.private_data is not None:
                binary.append(bitstring.pack(
                    "uint:8, bytes",
                    len(self.private_data), self.private_data))

            if adaptation_field_extension_length > 1:
                binary.append(bitstring.pack(
                    "uint:8, bool, bool, bool, pad:5",
                    adaptation_field_extension_length,
                    self.ltw_valid_flag is not None,
                    self.piecewise_rate is not None,
                    self.splice_type is not None))

                if self.ltw_valid_flag is not None:
                    binary.append(bitstring.pack(
                        "bool, uint:15",
                        self.ltw_valid_flag, self.ltw_offset))

                if self.piecewise_rate is not None:
                    binary.append(bitstring.pack(
                        "pad:2, uint:22", self.piecewise_rate))

                if self.splice_type is not None:
                    binary.append(bitstring.pack(
                        "uint:4, uint:3, bool, uint:15, bool, uint:15, bool",
                        self.splice_type,
                        self.dts_next_au >> 30, 1,
                        (self.dts_next_au >> 15) & 0x7FFF, 1,
                        self.dts_next_au & 0x7FFF, 1))
                    self.splice_type = data.read("uint:4")
                    self.dts_next_au = read_timestamp("DTS_next_AU", data)

            while (len(binary) / 8) < adaptation_field_length + 5:
                binary.append(bitstring.pack("uint:8", 0xFF))

        if self.payload is not None:
            binary.append(self.payload)

        if (len(binary) / 8) != 188:
            raise Exception(
                "TS Packet is %s bytes long, but should be exactly 188 bytes." \
                % (binary.bytelen))
        return binary.bytes

    def __repr__(self):
        return to_json(self)


class ProgramAssociationTable(object):
    PID = 0x00
    TABLE_ID = 0x00

    def __init__(self, data):
        data = BitStream(data)
        pointer_field = data.read("uint:8")
        if pointer_field:
            data.read(pointer_field)

        self.table_id = data.read("uint:8")
        if self.table_id != self.TABLE_ID:
            raise Exception(
                "table_id for PAT is {} but should be {}".format(
                    self.table_id, self.TABLE_ID))
        self.section_syntax_indicator = data.read("bool")
        self.private_indicator = data.read("bool")
        data.read(2)  # reserved
        section_length = data.read("uint:12")
        self.transport_stream_id = data.read("uint:16")
        data.read(2)  # reserved
        self.version_number = data.read("uint:5")
        self.current_next_indicator = data.read("bool")
        self.section_number = data.read("uint:8")
        self.last_section_number = data.read("uint:8")

        num_programs = (section_length - 9) // 4
        self.programs = OrderedDict()
        for _ in range(num_programs):
            program_number = data.read("uint:16")
            data.read(3)  # reserved
            pid = data.read("uint:13")
            self.programs[program_number] = pid
        data.read("uint:32") # crc
        calculated_crc = crc32(data.bytes[pointer_field + 1:data.bytepos])
        if calculated_crc != 0:
            raise Exception(
                "CRC of entire PAT should be 0, but saw %s." \
                % (calculated_crc))

        while data.bytepos < len(data.bytes):
            padding_byte = data.read("uint:8")
            if padding_byte != 0xFF:
                raise Exception("Padding byte at end of PAT was 0x{:X} but "
                                "should be 0xFF".format(padding_byte))

    def __repr__(self):
        return to_json(self)

    def __eq__(self, other):
        return isinstance(other, ProgramAssociationTable) \
            and self.__dict__ == other.__dict__


class Descriptor(object):
    TAG_CA_DESCRIPTOR = 9

    def __init__(self, tag):
        self.tag = tag
        self.contents = b""

    @staticmethod
    def parse(data):
        desc = Descriptor(data.read("uint:8"))
        length = data.read("uint:8")
        if desc.tag == desc.TAG_CA_DESCRIPTOR:
            desc.ca_system_id = data.read("bytes:2")
            data.read(3) # reserved
            desc.ca_pid = data.read("uint:13")
            desc.private_data_bytes = data.read((length - 4) * 8).bytes
        else:
            desc.contents = data.read(length * 8).bytes
        return desc

    @property
    def length(self):
        if self.tag == self.TAG_CA_DESCRIPTOR:
            return 4 + len(self.private_data_bytes)
        else:
            return len(self.contents)

    @property
    def size(self):
        return 2 + self.length

    @property
    def bytes(self):
        binary = bitstring.pack("uint:8, uint:8", self.tag, self.length)
        if self.tag == self.TAG_CA_DESCRIPTOR:
            binary.append(bitstring.pack(
                "bytes:2, pad:3, uint:13, bytes",
                self.ca_system_id, self.ca_pid, self.private_data_bytes))
        else:
            binary.append(self.contents)
        assert(len(binary) / 8 == self.size)
        return binary.bytes

    def __repr__(self):
        return to_json(self)

    def __eq__(self, other):
        return isinstance(other, Descriptor) \
            and self.__dict__ == other.__dict__

    @staticmethod
    def read_descriptors(data, size):
        total = 0
        descriptors = []
        while total < size:
            descriptor = Descriptor.parse(data)
            descriptors.append(descriptor)
            total += descriptor.size
        if total != size:
            raise Exception("Excepted {} bytes of descriptors, but got "
                            "{} bytes of descriptors.".format(size, total))
        return descriptors


class Stream(object):
    def __init__(self, data):
        self.stream_type = data.read("uint:8")
        data.read(3)  # reserved
        self.elementary_pid = data.read("uint:13")
        data.read(4)  # reserved
        es_info_length = data.read("uint:12")
        self.descriptors = Descriptor.read_descriptors(data, es_info_length)

    @property
    def size(self):
        total = 5
        for descriptor in self.descriptors:
            total += descriptor.size
        return total

    @property
    def bytes(self):
        es_info_length = 0
        for descriptor in self.descriptors:
            es_info_length += descriptor.size
        binary = bitstring.pack(
            "uint:8, pad:3, uint:13, pad:4, uint:12",
            self.stream_type, self.elementary_pid, es_info_length)
        for descriptor in self.descriptors:
            binary.append(descriptor.bytes)
        return binary.bytes

    def __eq__(self, other):
        return isinstance(other, Stream) \
            and self.__dict__ == other.__dict__

    def __repr__(self):
        return to_json(self.__dict__)


class ProgramMapTable(object):
    TABLE_ID = 0x02

    def __init__(self, data):
        data = BitStream(data)
        pointer_field = data.read("uint:8")
        if pointer_field:
            data.read(pointer_field)

        self.table_id = data.read("uint:8")
        if self.table_id != self.TABLE_ID:
            raise Exception(
                "table_id for PMT is {} but should be {}".format(
                    self.table_id, self.TABLE_ID))
        self.section_syntax_indicator = data.read("bool")
        self.private_indicator = data.read("bool")
        data.read(2)  # reserved
        section_length = data.read("uint:12")

        self.program_number = data.read("uint:16")
        data.read(2)  # reserved
        self.version_number = data.read("uint:5")
        self.current_next_indicator = data.read("bool")
        self.section_number = data.read("uint:8")
        self.last_section_number = data.read("uint:8")

        data.read(3)  # reserved
        self.pcr_pid = data.read("uint:13")

        data.read(4)  # reserved
        program_info_length = data.read("uint:12")
        self.descriptors = Descriptor.read_descriptors(
            data, program_info_length)

        self.streams = OrderedDict()
        while data.bytepos < section_length + 3 - 4:
            stream = Stream(data)
            if stream.elementary_pid in self.streams:
                raise Exception(
                    "PMT contains the same elementary PID more than once.")
            self.streams[stream.elementary_pid] = stream

        data.read("uint:32") # crc
        calculated_crc = crc32(data.bytes[pointer_field + 1:data.bytepos])
        if calculated_crc != 0:
            raise Exception(
                "CRC of entire PMT should be 0, but saw %s." \
                % (calculated_crc))

        while data.bytepos < len(data.bytes):
            padding_byte = data.read("uint:8")
            if padding_byte != 0xFF:
                raise Exception("Padding byte at end of PMT was 0x{:02X} but "
                                "should be 0xFF".format(padding_byte))

    @property
    def bytes(self):
        binary = bitstring.pack(
            "pad:8, uint:8, bool, bool, pad:2",
            self.TABLE_ID, self.section_syntax_indicator,
            self.private_indicator)

        program_info_length = 0
        for descriptor in self.descriptors:
            program_info_length += descriptor.size

        length = 13 + program_info_length
        for stream in self.streams.values():
            length += stream.size

        binary.append(bitstring.pack(
            "uint:12, uint:16, pad:2, uint:5, bool, uint:8, uint:8, pad:3," +
            "uint:13, pad:4, uint:12",
            length, self.program_number, self.version_number,
            self.current_next_indicator, self.section_number,
            self.last_section_number, self.pcr_pid, program_info_length))

        for descriptor in self.descriptors:
            binary.append(descriptor.bytes)
        for stream in self.streams.values():
            binary.append(stream.bytes)

        binary.append(bitstring.pack("uint:32", crc32(binary.bytes[1:])))
        return binary.bytes

    def __repr__(self):
        return to_json(self)

    def __eq__(self, other):
        return isinstance(other, ProgramMapTable) \
            and self.__dict__ == other.__dict__


class PESReader(object):
    def __init__(self):
        self.ts_packets = []
        self.length = None
        self.data = []

    def add_ts_packet(self, ts_packet):
        if not self.ts_packets and not ts_packet.payload_unit_start_indicator:
            logging.debug("First TS packet for PID 0x{:02X} does not have "
                          "payload_unit_start_indicator = 1. Ignoring this "
                          "packet.".format(ts_packet.pid))
            return None

        self.ts_packets.append(ts_packet)
        if ts_packet.payload:
            self.data.extend(ts_packet.payload)
        if self.length is None and len(self.data) >= 6:
            self.length, = struct.unpack("!xxxxH", bytes(self.data[:6]))
            self.length -= 6

        if len(self.data) < self.length:
            return None

        try:
            pes_packet = PESPacket(bytes(self.data), self.ts_packets)
        except Exception as e:
            logging.warning(e)
            pes_packet = None

        self.ts_packets = []
        self.data = []
        self.length = None
        return pes_packet


class StreamID(object):
    PROGRAM_STREAM_MAP = 0xBC
    PADDING = 0xBE
    PRIVATE_2 = 0xBF
    ECM = 0xF0
    EMM = 0xF1
    PROGRAM_STREAM_DIRECTORY = 0xFF
    DSMCC = 0xF2
    H222_1_TYPE_E = 0xF8

    @staticmethod
    def has_pes_header(sid):
        return sid != StreamID.PROGRAM_STREAM_MAP \
            and sid != StreamID.PADDING \
            and sid != StreamID.PRIVATE_2 \
            and sid != StreamID.ECM \
            and sid != StreamID.EMM \
            and sid != StreamID.PROGRAM_STREAM_DIRECTORY \
            and sid != StreamID.DSMCC \
            and sid != StreamID.H222_1_TYPE_E


class PESPacket(object):
    def __init__(self, data, ts_packets):
        self.bytes = data
        first_ts = ts_packets[0]
        self.pid = first_ts.pid
        self.byte_offset = first_ts.byte_offset
        self.size = len(ts_packets) * TSPacket.SIZE
        self.random_access = first_ts.random_access_indicator

        self.ts_packets = ts_packets
        data = BitStream(data)

        start_code = data.read("uint:24")
        if start_code != 0x000001:
            raise Exception("packet_start_code_prefix is 0x{:06X} but should "
                            "be 0x000001".format(start_code))

        self.stream_id = data.read("uint:8")
        pes_packet_length = data.read("uint:16")

        if StreamID.has_pes_header(self.stream_id):
            bits = data.read("uint:2")
            if bits != 2:
                raise Exception("First 2 bits of a PES header should be 0x2 "
                                "but saw 0x{:02X}'".format(bits))

            self.pes_scrambling_control = data.read("uint:2")
            self.pes_priority = data.read("bool")
            self.data_alignment_indicator = data.read("bool")
            self.copyright = data.read("bool")
            self.original_or_copy = data.read("bool")
            pts_dts_flags = data.read("uint:2")
            escr_flag = data.read("bool")
            es_rate_flag = data.read("bool")
            dsm_trick_mode_flag = data.read("bool")
            additional_copy_info_flag = data.read("bool")
            pes_crc_flag = data.read("bool")
            pes_extension_flag = data.read("bool")
            pes_header_data_length = data.read("uint:8")

            if pts_dts_flags & 2:
                bits = data.read("uint:4")
                if bits != pts_dts_flags:
                    raise Exception(
                        "2 bits before PTS should be 0x{:02X} but saw 0x{"
                        ":02X}".format(pts_dts_flags, bits))
                self.pts = read_timestamp("PTS", data)

            if pts_dts_flags & 1:
                bits = data.read("uint:4")
                if bits != 0x1:
                    raise Exception("2 bits before DTS should be 0x1 but saw "
                                    "0x{:02X}".format(bits))
                self.dts = read_timestamp("DTS", data)

            # skip the rest of the header and stuffing bytes
            data.bytepos = pes_header_data_length + 9
        if self.stream_id == StreamID.PADDING:
            self.payload = None
        else:
            self.payload = data.read("bytes")

    def __repr__(self):
        d = self.__dict__.copy()
        del d["bytes"]
        del d["ts_packets"]
        return to_json(d)
