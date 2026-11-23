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
