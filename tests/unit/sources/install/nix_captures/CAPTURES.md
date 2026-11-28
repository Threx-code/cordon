# nix_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| github.flake.lock | the flake.lock Nix wrote for a flake with one GitHub input (nix-systems/default) | output of the tool | nix flake lock, kept as written | b76e1439ed4358b19afdfb21338da98b20cf7688c26a10694a2fc5b060577a72 |
| gitlab-sourcehut.flake.lock | the flake.lock Nix wrote for a flake with a GitLab input (gitlab-org/cli) and a SourceHut input (~sircmpwn/scdoc) | output of the tool | nix flake lock, kept as written | bf8d0697483a7d40d9a1ead38b9ebe7307880c62984f2a2e5d7fa14a631cf7e3 |
| gitlab.flake.lock | the flake.lock Nix wrote for a flake with one GitLab input (pages/plain-html) | output of the tool | nix flake lock, kept as written | f8dbf980b25d391d7ae0a7b48f856e567e60f3a8061befb8631bf163fe034ead |
| nix-gitlab-pages-plain-html-87e8c32b.tar.gz | https://gitlab.com/api/v4/projects/pages%2Fplain-html/repository/archive.tar.gz?sha=87e8c32b8918a836c09475e0f668ea7c436d3758 | MIT (pages/plain-html) | curl with a generic User-Agent, kept as served | 78ea7b4791382c4969738dfaa39f7c210b783deee6813427f071707c71970756 |
| nix-sourcehut-scdoc-24be30ef.tar.gz | https://git.sr.ht/~sircmpwn/scdoc/archive/24be30ef17d5ca0162f11b35258c8fa2413d556a.tar.gz | MIT (~sircmpwn/scdoc) | curl with a generic User-Agent, kept as served | a702653842fd4cf67dfc368ddc16d95fecca7b75b24b562cd29159bb7f213d4d |
| nix-systems-default-d36eeed142f88b5a636f2e3856a53c61654cf29b.tar.gz | https://codeload.github.com/nix-systems/default/tar.gz/d36eeed142f88b5a636f2e3856a53c61654cf29b | MIT (nix-systems/default) | curl with a generic User-Agent, kept as served | 53787abab8ef6af68e3b283eb36a5871a929194118cbba97c9d947a067599de6 |
