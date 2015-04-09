# MPEG-TS Inspector

This is a debugging tool that parses and outputs the contents of MPEG-TS files. Currently, it understands TS packets, PAT sections, PMT sections, and PES packets.

## Setup

You will need `git` and `python3` installed.

    git clone https://github.com/brendanlong/mpeg-ts-inspector.git
    cd mpeg-ts-inspector
    ./setup.sh # installs a Python 3 virtualenv with bitstring and crcmod

## Usage

Activate the virtualenv with:

    source bin/activate

See current options with `./ts_inspect.py -h`.

## Examples

### Show all TS packets, PES packets, PAT sections and PMT sections

    ./ts_inspect.py --show-ts --show-pes --show-pat --show-pmt somefile.ts

### Show TS and PES packets for PID's 33 and 34

    ./ts_inspect.py --show-ts --show-pes --filter 33,34 somefile.ts
