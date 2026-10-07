#!/bin/sh
# Regenerates the real-world opam conformance case: a dune project generates app.opam (with a
# template adding a git pin-depends), opam installs its dependencies (test ones included) into the
# image's switch, and `opam lock` writes app.opam.locked. opam's own `opam list --required-by`
# over the installed switch -- independent of the lock -- is the authoritative inventory. Only
# the dependencies are built; the project's own code is never built or run. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" ocaml/opam:debian-12-ocaml-5.2 sh /conformance/generate/opam.sh
set -eu
OUT=/conformance/cases/opam/real-dune-project
rm -rf /tmp/o && mkdir -p /tmp/o/bin && cd /tmp/o
export OPAMYES=1 OPAMCOLOR=never

cat > dune-project <<'EOF'
(lang dune 3.0)
(name app)
(generate_opam_files true)
(source (github acme/app))
(license MIT)
(authors "Conformance Fixture")
(maintainers "fixture@example.invalid")

(package
 (name app)
 (synopsis "A conformance fixture")
 (depends
  (ocaml (>= 4.14))
  dune
  (fmt (>= 0.9))
  (cmdliner (< 2.0))
  uutf
  (astring (= 0.8.5))
  (mtime (and (>= 2.0) (< 3.0)))
  (alcotest :with-test)
  (odoc :with-doc)))
EOF
cat > app.opam.template <<'EOF'
depexts: [
  ["libgmp-dev"] {os-family = "debian"}
]
pin-depends: [
  ["uutf.1.0.3" "git+https://github.com/dbuenzli/uutf.git#v1.0.3"]
]
EOF
printf '(executable (name main))\n' > bin/dune
printf 'let () = ()\n' > bin/main.ml

opam update >/tmp/opam.log 2>&1
opam install dune >>/tmp/opam.log 2>&1 || { tail -20 /tmp/opam.log; exit 1; }
eval "$(opam env)"
dune build app.opam >>/tmp/opam.log 2>&1 || { tail -20 /tmp/opam.log; exit 1; }
opam install . --deps-only --with-test >>/tmp/opam.log 2>&1 || { tail -30 /tmp/opam.log; exit 1; }
opam lock ./app.opam >>/tmp/opam.log 2>&1 || { tail -20 /tmp/opam.log; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT/bin"
cp dune-project app.opam app.opam.template app.opam.locked "$OUT/"
cp bin/dune bin/main.ml "$OUT/bin/"

# opam list names packages: pin the project (without building it) so it has one.
opam pin add --no-action app . >>/tmp/opam.log 2>&1
opam list --required-by=app --recursive --installed --with-test --columns=name,version --short --normalise >/tmp/required.txt 2>>/tmp/opam.log
# The compiler and the virtual packages describing it (base-unix, base-domains, ...; version
# `base`) are a platform requirement the switch meets. The compiler reaches the base-* packages
# through `post` dependencies, which --required-by does not follow, so the lock lists more of them.
awk -v out="$OUT/authoritative.json" '
  BEGIN { printf "{\n \"tool\": \"opam list --required-by --recursive --installed --with-test\",\n \"packages\": [" > out }
  { printf "%s\"%s@%s\"", (NR > 1 ? ", " : ""), $1, $2 >> out }
  END {
    printf "],\n \"exclude\": {\"dependency_type\": {\"platform\": \"the OCaml compiler and its virtual feature packages: met by the switch, recorded as platform requirements\"}},\n" >> out
    printf " \"ignore\": {\"ocaml\": \"the compiler\", \"ocaml-base-compiler\": \"the compiler\", \"ocaml-config\": \"the compiler\", \"base-threads\": \"a virtual package of the compiler\", \"base-unix\": \"a virtual package of the compiler\"}\n}\n" >> out
  }
' /tmp/required.txt
cat "$OUT/authoritative.json"
cat app.opam.locked
echo done
