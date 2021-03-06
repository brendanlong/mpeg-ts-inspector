#!/usr/bin/env python3
import argparse
import logging
from ts import *
import sys


class OmniSet(object):
    def __contains__(self, x):
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mpeg_ts_file", help="The file to read")
    parser.add_argument(
        "--show-ts", help="Output TS packets.", action="store_true",
        default=False)
    parser.add_argument(
        "--show-pes", help="Output PES packets.", action="store_true",
        default=False)
    parser.add_argument(
        "--show-pat", help="Output PAT sections.", action="store_true",
        default=False)
    parser.add_argument(
        "--show-pmt", help="Output PMT sections.", action="store_true",
        default=False)
    parser.add_argument(
        "--as-c-array", action="store_true", default=False,
        help="Output sections as C arrays instead of pretty-printing.")
    parser.add_argument(
        "--filter", type=lambda x: list(map(int, x.split(","))),
        default=OmniSet(),
        help="Only show output for PIDs in this comma-separated list.")
    parser.add_argument(
        "--no-wait", help="Don't want for input after output",
        action="store_true", default=False)
    parser.add_argument(
        "--verbose", "-v", action="store_true", default=False,
        help="Enable verbose output.")
    args = parser.parse_args()

    logging.basicConfig(
        format='%(levelname)s: %(message)s',
        level=logging.DEBUG if args.verbose else logging.INFO)

    def wait():
        if args.no_wait:
            pass
        else:
            input()

    def output(o):
        print(o)
        if args.as_c_array:
            print("uint8_t %s_bytes[] = {%s};" %
                  (type(o).__name__.lower(), ", ".join(map(str, o.bytes))))

    pmt_pids = set()
    pes_readers = {}
    ts_reader = read_ts(args.mpeg_ts_file)
    while True:
        try:
            ts_packet = next(ts_reader)
        except StopIteration:
            break
        except Exception as e:
            print("Error reading TS packet: %s" % e)
            continue

        if args.show_ts and ts_packet.pid in args.filter:
            output(ts_packet)
            wait()
        if ts_packet.pid == ProgramAssociationTable.PID:
            try:
                pat = ProgramAssociationTable(ts_packet.payload)
                if args.show_pat and ts_packet.pid in args.filter:
                    output(pat)
                    wait()
                pmt_pids.update(pat.programs.values())
            except Exception as e:
                print("Error reading PAT: %s" % e)

        elif ts_packet.pid in pmt_pids:
            try:
                pmt = ProgramMapTable(ts_packet.payload)
                if args.show_pmt and ts_packet.pid in args.filter:
                    output(pmt)
                    wait()
                for pid in pmt.streams:
                    if pid not in pes_readers:
                        pes_readers[pid] = PESReader()
            except Exception as e:
                print("Error reading PMT: %s" % e)

        elif args.show_pes and ts_packet.pid in pes_readers:
            try:
                pes_packet = pes_readers[ts_packet.pid].add_ts_packet(ts_packet)
                if pes_packet and ts_packet.pid in args.filter:
                    output(pes_packet)
                    wait()
            except Exception as e:
                print("Error reading PES packet: %s" % e)
