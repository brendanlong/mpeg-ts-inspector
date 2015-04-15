import json

from base64 import b64encode


# http://stackoverflow.com/a/4256027/212555
def del_none(o):
    """
    Delete keys with the value ``None`` in a dictionary, recursively.

    This alters the input so you may wish to ``copy`` the dict first.
    """
    if isinstance(o, dict):
        d = o.copy()
    else:
        d = o.__dict__.copy()
    for key, value in list(d.items()):
        if value is None:
            del d[key]
        elif isinstance(value, dict):
            del_none(value)
    return d


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
    return json.dumps(del_none(o), default=_to_json_dict, indent=4)
