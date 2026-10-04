# Inert corpus sample: never executed. Environmental keying: the payload runs only in one region.
import base64
import time

zone = time.tzname[0]
if zone in ('MSK',) or __import__('os').environ.get('LANG', '').startswith('ru_RU'):
    exec(base64.b64decode(b'cHJpbnQoJ2lub2N1b3VzJyk='))
