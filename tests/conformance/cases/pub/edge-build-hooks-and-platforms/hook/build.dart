import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    await CBuilder.library(name: 'native_sum', assetName: 'native_sum.dart', sources: ['src/sum.c'])
        .run(input: input, output: output);
  });
}
