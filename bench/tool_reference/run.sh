#!/bin/sh
# Runs each ecosystem's own tool over the collected files, each in that tool's official image.
# Host side: the Docker CLI only. Usage: bench/tool_reference/run.sh [ecosystem ...]
set -u
here=$(cd "$(dirname "$0")" && pwd)
volume=${CORDON_TOOL_VOLUME:-cordon-tool-agreement}
run() { docker run --rm -v "$volume:/vol" -v "$here:/ref:ro" --entrypoint sh "$@"; }
for eco in ${*:-terraform helm julia opam conda ansible nix bazel conan vcpkg cran actions}; do
  echo "== $eco"
  case $eco in
    terraform) run golang:1.23-bookworm -c 'ln -s /vol/tool-agreement /data; sh /ref/terraform.sh' ;;
    helm)      run alpine/helm:3.16.2 -c 'ln -s /vol/tool-agreement /data; sh /ref/helm.sh' ;;
    julia)     run julia:1.11 -c 'ln -s /vol/tool-agreement /data; julia /ref/julia.jl' ;;
    opam)      run --user root -e OPAMROOTISOK=1 -e OPAMROOT=/home/opam/.opam ocaml/opam:debian-12-ocaml-5.2 -c 'ln -s /vol/tool-agreement /data; sh /ref/opam.sh' ;;
    conda)     run continuumio/miniconda3:24.7.1-0 -c 'ln -s /vol/tool-agreement /data; python -I /ref/read_conda.py' ;;
    ansible)   run python:3.12-slim -c 'pip install -q ansible-core==2.17.5 >/dev/null 2>&1; ln -s /vol/tool-agreement /data; python -I /ref/read_ansible.py' ;;
    nix)       run nixos/nix:2.24.9 -c 'sh /ref/nix.sh' ;;
    bazel)     run golang:1.23-bookworm -c 'go install github.com/bazelbuild/bazelisk@v1.22.1 >/dev/null 2>&1; ln -s "$(go env GOPATH)/bin/bazelisk" /usr/local/bin/bazelisk; ln -s /vol/tool-agreement /data; sh /ref/bazel.sh' ;;
    conan)     run python:3.12-slim -c 'pip install -q conan==2.8.1 >/dev/null 2>&1; ln -s /vol/tool-agreement /data; python -I /ref/read_conan.py' ;;
    vcpkg)     run debian:bookworm-slim -c 'ln -s /vol/tool-agreement /data; sh /ref/vcpkg.sh' ;;
    cran)      run rocker/r-ver:4.4.1 -c 'R -q -e "install.packages(\"renv\", repos = \"https://cloud.r-project.org\")" >/dev/null 2>&1; ln -s /vol/tool-agreement /data; Rscript /ref/cran.R' ;;
    actions)   run python:3.12-slim -c 'ln -s /vol/tool-agreement /data; python -I /ref/read_actions.py' ;;
  esac
done
