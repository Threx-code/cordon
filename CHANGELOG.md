# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--staged`, `--tracked` and `--git-diff REF`, through a file-source
  abstraction. Staged mode reads blobs from the git index rather than the
  working tree.
- `cordon baseline create|compare` and `scan --baseline PATH`.
- `rules.disabled` in configuration, accepting any rule id.
- `cordon rules list` and `rules show` report rules declared by detectors, not
  only those in YAML packs.
- `python -m cordon`.
- Cache entries are authenticated with a per-machine HMAC.
- `per_file_timeout`, `max_findings`, `max_memory_bytes` and `max_path_bytes`
  are enforced.

### Fixed
- A NUL byte no longer disables content detection. Binary classification is
  decided from a file's identity, never from its contents.
- A reporting threshold can no longer weaken the failure gate.
- Pattern validation walks the parsed regex, so nesting, lookaheads and
  non-capturing groups cannot hide a catastrophic shape.
- Prefilter extraction no longer mis-parses bounded quantifiers, which had
  rendered affected rules permanently inert.
- Command-line overrides are re-checked against the organisation ceiling.
- A third-party distribution can no longer shadow a built-in detector.
- The parallel path honours detector configuration, so `-j 1` and `-j 8` agree.
- File loading opens with `O_NOFOLLOW` and checks the descriptor, closing a
  time-of-check/time-of-use window.
- Archive member rejections are reported instead of discarded.
- Secret detection matches unquoted assignments and URL userinfo.
- Kubernetes manifests are identified by content rather than by directory name.
- `curl | sh` is detected in plain shell scripts, not only in CI and container
  files.
- Typosquat detection no longer flags companion packages such as `vuex`.
- The YAML subset parser no longer misparses URLs in lists, and refuses
  duplicate keys.
- Limits are validated for type and range.
- Reports no longer contain absolute filesystem paths.

## [0.1.0]

Initial release.
