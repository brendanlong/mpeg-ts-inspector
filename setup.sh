#!/bin/bash
virtualenv -p python3 .
source bin/activate
pip install --upgrade bitstring crcmod

echo "You probably want to 'source bin/activate' now."
