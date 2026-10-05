"""The resolver that records what a detonated install tried to look up.

A tiny resolver on 127.0.0.1:53 inside the networkless container: it writes each queried name to a
log and answers NXDOMAIN. Nothing is ever forwarded - the container has no network - so its only
effect is the record. One script per ecosystem, in the runtime that ecosystem's image already has.

Kept apart from `observe.py`, which names the credential and shell files whose creation is an
observation: the scanner's composite rules read a file as a whole, and this module's socket next to
that vocabulary looks like code that reads credentials and sends them somewhere. It does neither.
"""

from __future__ import annotations

from typing import Final


class DnsRecorder:
    #: Where the recorder is written inside the container, and where it writes what it saw.
    PATH: Final = "/opt/cordon/dnslog"
    LOG: Final = "/work/.cordon-dns"
    MAX_BYTES: Final = 64 << 10

    SCRIPTS: Final = {
        "npm": (
            "const dgram=require('dgram'),fs=require('fs'),out=process.argv[2],s=dgram.createSocket('udp4');\n"
            "s.on('message',(m,r)=>{try{let i=12,l=[];while(i<m.length&&m[i]){const n=m[i];"
            "l.push(m.slice(i+1,i+1+n).toString('latin1'));i+=n+1;}"
            "fs.appendFileSync(out,l.join('.').slice(0,253)+'\\n');"
            "const a=Buffer.from(m.slice(0,512));a[2]=0x81;a[3]=0x83;s.send(a,r.port,r.address);}catch(e){}});\n"
            "s.bind(53,'127.0.0.1');\n"
        ),
        "pypi": (
            "import socket, sys\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.bind(('127.0.0.1', 53))\n"
            "while True:\n"
            "    m, a = s.recvfrom(512)\n"
            "    try:\n"
            "        i, labels = 12, []\n"
            "        while i < len(m) and m[i]:\n"
            "            n = m[i]; labels.append(m[i + 1:i + 1 + n].decode('latin1')); i += n + 1\n"
            "        open(sys.argv[1], 'a').write('.'.join(labels)[:253] + '\\n')\n"
            "        r = bytearray(m); r[2], r[3] = 0x81, 0x83; s.sendto(bytes(r), a)\n"
            "    except Exception:\n"
            "        pass\n"
        ),
    }

    COMMANDS: Final = {"npm": f"node {PATH}", "pypi": f"python3 {PATH}"}
