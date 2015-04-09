#!/usr/bin/env python3
import argparse
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
        "--filter", type=lambda x: list(map(int, x.split(","))),
        default=OmniSet(),
        help="Only show output for PIDs in this comma-separated list.")
    parser.add_argument(
        "--no-wait", help="Don't want for input after output",
        action="store_true", default=False)
    args = parser.parse_args()

    def wait():
        if args.no_wait:
            pass
        else:
            input()

    pmt_pids = set()
    pes_readers = {}
    for ts_packet in read_ts(args.mpeg_ts_file):
        if args.show_ts and ts_packet.pid in args.filter:
            print(ts_packet)
            wait()
        if ts_packet.pid == ProgramAssociationTable.PID:
            pat = ProgramAssociationTable(ts_packet.payload)
            if args.show_pat and ts_packet.pid in args.filter:
                print(pat)
                wait()
            pmt_pids.update(pat.programs.values())

        elif ts_packet.pid in pmt_pids:
            pmt = ProgramMapTable(ts_packet.payload)
            if args.show_pmt and ts_packet.pid in args.filter:
                print(pmt)
                wait()
            for pid in pmt.streams:
                if pid not in pes_readers:
                    pes_readers[pid] = PESReader()

        elif args.show_pes and ts_packet.pid in pes_readers:
            pes_packet = pes_readers[ts_packet.pid].add_ts_packet(ts_packet)
            if pes_packet and ts_packet.pid in args.filter:
                print(pes_packet)
                wait()
