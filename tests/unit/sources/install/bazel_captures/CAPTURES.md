# bazel_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| MODULE.bazel.lock | cut from the MODULE.bazel.lock of github.com/bazelbuild/bazel: four registry entries and the generated repositories of one module extension (`async_profiler_repos`) | Apache-2.0 (bazelbuild/bazel) | the real entries kept unchanged, the rest of the file removed | 022cfa1b965da96d9ab8717dc99c7a6b669091748507b4c00ae163b68750f68d |
| abseil-cpp-20250814.1-MODULE.bazel | https://bcr.bazel.build/modules/abseil-cpp/20250814.1/MODULE.bazel | Apache-2.0 (Bazel Central Registry) | curl with a generic User-Agent, kept as served | 51f2312901470cdab0dbdf3b88c40cd21c62a7ed58a3de45b365ddc5b11bcab2 |
| abseil-cpp-20250814.1-source.json | https://bcr.bazel.build/modules/abseil-cpp/20250814.1/source.json | Apache-2.0 (Bazel Central Registry) | curl with a generic User-Agent, kept as served | cea3901d7e299da7320700abbaafe57a65d039f10d0d7ea601c4a66938ea4b0c |
| bazel_skylib-1.9.0-MODULE.bazel | https://bcr.bazel.build/modules/bazel_skylib/1.9.0/MODULE.bazel | Apache-2.0 (Bazel Central Registry) | curl with a generic User-Agent, kept as served | 72997b29dfd95c3fa0d0c48322d05590418edef451f8db8db5509c57875fb4b7 |
| bazel_skylib-1.9.0-source.json | https://bcr.bazel.build/modules/bazel_skylib/1.9.0/source.json | Apache-2.0 (Bazel Central Registry) | curl with a generic User-Agent, kept as served | 7ad77c1e8c1b84222d9b3f3cae016a76639435744c19330b0b37c0a3c9da7dc0 |
