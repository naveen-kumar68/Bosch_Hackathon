# Tool lock

Environment: native Windows x86_64, PowerShell; Docker Linux engine.
Versions verified before feature implementation, 2026-11-23.

| Tool | Exact version | Verification |
|---|---|---|
| Python | 3.12.12 | uv-managed CPython; installed successfully |
| uv | 0.9.8 (85c5d3228) | `uv --version` |
| Cargo | 1.91.1 (ea2d97820) | `cargo --version` |
| rustc | 1.91.1 (ed61e7d7e) | `rustc --version` |
| cargo-cyclonedx | 0.5.10 | `cargo-cyclonedx cyclonedx --version` |
| Syft | 1.57.2 (1a72047fd46c72e0a12ee77e24b23d2316753d08) | `syft version` |
| CycloneDX CLI | 0.33.1 (b3cfa4b0edc356dad07e0b6e7ab6da0a94af0246) | `cyclonedx --version` |
| cyclonedx-py | 9.0.0 | `cyclonedx-py --version` |
| pyspdxtools | 0.8.5 | Distribution metadata and `pyspdxtools --help` |
| Docker client/server | 28.4.0 / 28.4.0 | `docker version` |
| Git | 2.49.0.windows.1 | `git --version` |

Python library versions and hashes: `uv.lock` (install using `uv sync --locked`).
Downloaded scanner binaries live in ignored `.tools/`.

Release origins:

- `anchore/syft`, tag `v1.57.2`, asset `syft_1.57.2_windows_amd64.zip`.
  SHA256 verified against the release's `syft_1.57.2_checksums.txt`.
- `CycloneDX/cyclonedx-rust-cargo`, tag `cargo-cyclonedx-0.5.10`, asset
  `cargo-cyclonedx-x86_64-pc-windows-msvc.zip`. SHA256 verified against the
  accompanying `.sha256` release asset.
- `CycloneDX/cyclonedx-cli`, tag `v0.33.1`, asset `cyclonedx-win-x64.exe`.
  Local SHA256 recorded below; no separate upstream checksum asset was provided.

| Artifact | SHA256 |
|---|---|
| syft_1.57.2_windows_amd64.zip | `0a10e03ffd124c304fd7e7491262dba2e5f68eb12378b106d7525146675b2e3a` |
| cargo-cyclonedx-x86_64-pc-windows-msvc.zip | `b0cdf58875a4b3c83e13fbea19eb6a85d63498aeab90f50456179173c370b3ce` |
| cyclonedx-win-x64.exe | `9b360974c41a5d612eb026fb5e3bb1fa28e08865f7a4f915665b8bc94bd3bc31` |

Additional verified tools: SQLite 3.50.4; GitHub CLI 2.95.0.
Library imports, `pytest --version` (9.2.0), and `ruff --version` (0.17.6) passed.

## Checkpoint 2 tools (installation checks in progress)

| Tool | Pin | Verification status |
|---|---|---|
| OSV-Scanner | 2.7.1 | Native Windows version check passed; release checksum matched |
| Grype | 0.122.1 | Native version/checksum checks passed; vulnerability DB update completed |
| zizmor | 1.33.1 | Native Windows version check passed |
| cargo-audit | 0.23.0 | Installed with --locked; `cargo-audit audit --version` passed |
| GuardDog | 3.2.0 | Offline container help passed; cache refresh unavailable under network isolation |
| Semgrep CE | 1.186.0 | Offline container version check returned 1.186.0 |
| cvss | 3.6 | Python import passed |
| rapidfuzz | 3.14.6 | Python import passed |
| detect-secrets | 1.5.0 | Version check and import passed |
| httpx | 0.28.1 | Python import passed |
| openai | 3.57.0 | Python import passed; no API call made |
| python-dotenv | 1.2.4 | Python import passed |
| pip-audit | 2.10.1 | Version check passed |

GuardDog immutable scanner image:
`ghcr.io/datadog/guarddog@sha256:3dbc783f65f508b95222101cb2cd84d1d5f3e3675e42d6f1329bb9b8a99c8998`.

Semgrep immutable scanner image:
`semgrep/semgrep@sha256:6e1b04340e60e910fbb4ddbf3c857ab0918f064417ad5ac530014ccb3cf8c8f1`.

| Downloaded artifact | SHA256 |
|---|---|
| osv-scanner_windows_amd64.exe | `7121dcf420aefbbf89a7f0050c4d3094e079ff93afd334dfc96f16b02ec85800` |
| grype_0.122.1_windows_amd64.zip | `24e19d6378782d2da343b80c632e342bcdd3bd1bf44e415a0ff81cf85ce1043a` |
| zizmor-x86_64-pc-windows-msvc.zip | `f02ebeedf651da468b4de19d31f0609050af74e11be41dc46d82e355cf44f68b` |

OSV and Grype hashes were checked against release checksum assets; zizmor's hash
is a local reproducibility record, not independently authenticated provenance.

OSV scans must explicitly disable Rust call analysis; its own help states that
enabling Rust call analysis runs build scripts. Use lockfiles and `--no-resolve`.
