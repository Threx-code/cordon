# cocoapods_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| AFNetworking-2.7.0.podspec.json | https://cdn.cocoapods.org/Specs/a/7/5/AFNetworking/2.7.0/AFNetworking.podspec.json | MIT (AFNetworking) | curl with a generic User-Agent, kept as served | 17667b7624682f2983770770ccd8f6c570fa8d9842cbad621ca588ad938ee8f4 |
| Interstellar-ca22646f.tar.gz | https://codeload.github.com/artsy/Interstellar/tar.gz/ca22646f5a8449795fba3d3436a045da0aeb5949 | MIT (artsy/Interstellar) | curl with a generic User-Agent, kept as served | ebbfbc65a9d8d2bb0561459470511be4e02de88f2b40e5509cb0aedf011a3824 |
| afnetworking.Podfile.lock | lines of the Podfile.lock of github.com/artsy/eigen (AFNetworking) | MIT (artsy/eigen) | the real lines of each section kept, the rest of the file removed | f4375e74736097f565bb5a57d47dae25e8c2df77a7491942476acc5c1ddc3ae5 |
| boost.Podfile.lock | lines of the Podfile.lock of github.com/artsy/eigen (boost, a :path pod) | MIT (artsy/eigen) | the real lines of each section kept, the rest of the file removed | c16ef47862bf633e09ff32b3989b8b3b33880de3e3983c023771097d51022703 |
| braze.Podfile.lock | lines of the Podfile.lock of github.com/artsy/eigen (BrazeKit, a podspec-URL pod) | MIT (artsy/eigen) | the real lines of each section kept, the rest of the file removed | 148ed329b9ef5b09d6ffde9062d5ff4a9cb2bc7aa5b3646531f8181955a055cf |
| interstellar.Podfile.lock | lines of the Podfile.lock of github.com/artsy/eigen (Interstellar, a git pod) | MIT (artsy/eigen) | the real lines of each section kept, the rest of the file removed | 63d4542ce7e27c5af80ea06dd9bc937227fdb67e85db09dca1e44e9d1eea4812 |
