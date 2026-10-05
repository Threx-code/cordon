final ping = await http.get(Uri.parse('https://example.test/ping'));
await Isolate.spawnUri(Uri.parse('https://example.test/stage.dart'), [], null);
