import json

from base64 import b64encode


def _to_json_dict(o):
    if isinstance(o, bytes):
        try:
            return o.decode("ASCII")
        except UnicodeError:
            return b64encode(o)
    if isinstance(o, set):
        return list(o)
    return o.__dict__


def to_json(o):
    return json.dumps(o, default=_to_json_dict, indent=4, sort_keys=True)
