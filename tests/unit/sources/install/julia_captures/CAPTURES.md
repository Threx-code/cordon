# julia_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| JSON-1.13.4.tar.gz | https://pkg.julialang.org/package/682c06a0-de6a-54ab-a142-c8b1cf79cde6/06d90f699285d055e34f0b014636a75a17ff2252 | MIT (JuliaIO/JSON.jl) | curl with a generic User-Agent, kept as served | e0315911b0cbf417aa334780d7a77b3d9d18b6ed8f052f162fcb6eff6073f4b4 |
| Manifest.toml | the Manifest.toml of github.com/SciML/LinearSolve.jl | MIT (SciML/LinearSolve.jl) | curl with a generic User-Agent, kept as served | 61110ec1271ac7384fad0d6e5757efcb76c47fac12e2a01e38e8b8f561ec3e9b |
| Project.toml | the Project.toml of github.com/SciML/LinearSolve.jl | MIT (SciML/LinearSolve.jl) | curl with a generic User-Agent, kept as served | 45071a8dafb541c1e29faf91314396ac76478a15913c810d8b7ab955ee11712d |
