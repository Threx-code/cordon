# Real executables and the module values YARA gives them

`expected.json` is yara-python 4.5.1's own `pe`, `elf` and `dotnet` module data for each file
(`modules_callback`), and the results of the module functions it lists (`console.log`), recorded
once; `test_yara_modules.py` holds Cordon's engine to them. Every file is legitimate,
redistributable software, taken unchanged from a public npm package:

| file | is | licence | from |
|---|---|---|---|
| `cpython-wmi.pyd` | CPython's `_wmi` extension (signed, countersigned; resources, Rich header, PDB path, exports, delay-load imports) | PSF License 2.0 | `@backtomyfuture/exchange-cli-win32-x64` 0.2.11 |
| `amazon-lambda-core.dll` | AWS Lambda .NET core library (signed, countersigned, .NET metadata) | Apache License 2.0 | `@sstlv/sst` 2.26.6 |
| `system-runtime-compilerservices-unsafe.dll` | .NET `System.Runtime.CompilerServices.Unsafe` (signed, .NET metadata) | MIT | `@sstlv/sst` 2.26.6 |
| `libffi-raw_api.o` | libffi's `raw_api.c`, compiled (ELF symbols: `telfhash`, `import_md5`) | MIT | `@jpruden/ffi-napi` 2.4.6 |
