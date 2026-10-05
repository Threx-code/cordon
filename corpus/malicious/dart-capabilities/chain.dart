final packed = base64Decode(blob);
final cmd = utf8.decode(gzip.decode(packed));
await Process.run('sh', ['-c', cmd]);
