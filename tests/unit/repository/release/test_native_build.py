"""The build backend's native step (`cordon_build.Native`): a project's own C extension compiled with
the interpreter's compiler and the hardening flags into a platform-tagged wheel, and the pure wheel
when asked or when there is no compiler. Built on a small project made here, so the scanner's own
extension is not needed to test the backend."""

from __future__ import annotations

import importlib.util
import os
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from support import ROOT

SOURCE = r"""
#define PY_SSIZE_T_CLEAN
#include <Python.h>

static PyObject *twice(PyObject *self, PyObject *arg) {
    (void)self;
    long value = PyLong_AsLong(arg);
    if (value == -1 && PyErr_Occurred()) return NULL;
    return PyLong_FromLong(value * 2);
}

static PyMethodDef methods[] = {{"twice", twice, METH_O, "double"}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_probe", NULL, -1, methods,
                                    NULL, NULL, NULL, NULL};
PyMODINIT_FUNC PyInit__probe(void) { return PyModule_Create(&module); }
"""

PYPROJECT = """
[build-system]
requires = []
build-backend = "cordon_build"

[project]
name = "probe-pkg"
dynamic = ["version"]
requires-python = ">=3.11"

[tool.cordon-build]
version-file = "src/probe/__init__.py"
packages = ["probe"]

[[tool.cordon-build.native]]
name = "probe._probe"
sources = ["src/probe/_probe.c"]
"""


class Kit:
    @staticmethod
    def backend() -> Any:
        sys.path.insert(0, str(ROOT / "scripts" / "backend"))
        try:
            import cordon_build
        finally:
            sys.path.pop(0)
        return cordon_build

    @staticmethod
    def project(root: Path) -> Path:
        (root / "src" / "probe").mkdir(parents=True)
        (root / "src" / "probe" / "__init__.py").write_text(
            '__version__ = "0.1.0"\n', encoding="utf-8"
        )
        (root / "src" / "probe" / "_probe.c").write_text(SOURCE, encoding="utf-8")
        (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        (root / "MANIFEST.in").write_text("", encoding="utf-8")
        return root


needs_compiler = pytest.mark.skipif(
    Kit.backend().Native.compiler() is None, reason="no C compiler in this environment"
)


class TestNativeBuild:
    @needs_compiler
    def test_the_extension_is_compiled_into_a_platform_wheel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = Kit.project(tmp_path / "p")
        monkeypatch.chdir(root)
        monkeypatch.delenv("CORDON_BUILD_PURE", raising=False)
        name = Kit.backend().build_wheel(str(tmp_path))
        assert "py3-none-any" not in name and name.startswith("probe_pkg-0.1.0-cp")
        wheel = zipfile.ZipFile(tmp_path / name)
        extensions = [n for n in wheel.namelist() if n.startswith("probe/_probe")]
        assert len(extensions) == 1
        assert b"Root-Is-Purelib: false" in wheel.read("probe_pkg-0.1.0.dist-info/WHEEL")
        built = tmp_path / "x" / Path(extensions[0]).name
        built.parent.mkdir()
        built.write_bytes(wheel.read(extensions[0]))
        spec = importlib.util.spec_from_file_location("_probe", built)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.twice(21) == 42

    @needs_compiler
    def test_the_same_tree_builds_the_same_wheel_twice(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = Kit.project(tmp_path / "p")
        monkeypatch.chdir(root)
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        first, second = tmp_path / "a", tmp_path / "b"
        first.mkdir()
        second.mkdir()
        a = (first / Kit.backend().build_wheel(str(first))).read_bytes()
        b = (second / Kit.backend().build_wheel(str(second))).read_bytes()
        assert a == b

    def test_asked_for_pure_it_builds_the_pure_wheel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = Kit.project(tmp_path / "p")
        monkeypatch.chdir(root)
        monkeypatch.setenv("CORDON_BUILD_PURE", "1")
        name = Kit.backend().build_wheel(str(tmp_path))
        assert name == "probe_pkg-0.1.0-py3-none-any.whl"
        wheel = zipfile.ZipFile(tmp_path / name)
        assert not [n for n in wheel.namelist() if n.endswith((".so", ".pyd"))]

    def test_the_sdist_carries_the_c_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import tarfile

        root = Kit.project(tmp_path / "p")
        monkeypatch.chdir(root)
        name = Kit.backend().build_sdist(str(tmp_path))
        with tarfile.open(tmp_path / name) as sdist:
            assert "probe_pkg-0.1.0/src/probe/_probe.c" in sdist.getnames()

    def test_the_platform_tag_can_be_set_for_ci(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CORDON_WHEEL_PLATFORM", "manylinux_2_28_x86_64")
        tag = Kit.backend().Native.tag()
        assert tag.endswith("-manylinux_2_28_x86_64") and tag.startswith("cp")
        assert os.environ["CORDON_WHEEL_PLATFORM"] == "manylinux_2_28_x86_64"
