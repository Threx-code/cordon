final cmd = utf8.decode(base64Decode(blob));
await Process.run('sh', ['-c', cmd]);
