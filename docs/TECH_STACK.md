# Checkpoint 1 technology decisions

## Environment decision

The project owner authorized native Windows + PowerShell instead of WSL2 Ubuntu
on 2026-11-23. The corresponding acceptance checks will run on Windows; Linux
portability is checked separately in CI. Docker Desktop's existing Linux engine
is used only for pulling and inspecting images. Target code is never executed.

The owner selected **all Cargo features** for complete optional-dependency
coverage. Resolution uses `cargo metadata --format-version 1 --locked
--all-features`; the SBOM and `cargo tree` oracle use the same feature scope and
all platforms. Lockfile entries absent even from that resolution remain explicitly
unreachable inventory records; their build-script/proc-macro flags are unknown.

All project libraries and scanner tools below have OSI-approved licenses. Docker
Engine/CLI are Apache-2.0; the pre-existing Docker Desktop host application has
separate proprietary terms and is not redistributed by this project.

| Tool | Version | Licence | Used for | Why chosen | Alternative rejected (and why) |
|---|---|---|---|---|---|
| Python | 3.12.12 | PSF-2.0 | Application runtime | Scanner integration and typed models | Rust application: slower integration work for this checkpoint |
| uv | 0.9.8 | MIT OR Apache-2.0 | Environments and lockfile | Fast reproducible installs | pip requirements: no resolver lock by default; Poetry: more setup |
| Typer | 0.29.2 | MIT | CLI | Typed commands and help | argparse: more manual validation |
| Pydantic | 2.14.4 | MIT | Models and JSON Schema | Explicit validated evidence contracts | dataclasses: no runtime validation |
| packageurl-python | 0.17.6 | MIT | Canonical package IDs | Ecosystem-neutral identity | Name strings: collisions across ecosystems |
| Cargo / rustc | 1.91.1 | MIT OR Apache-2.0 | Locked metadata/fetch; tree test oracle | Authoritative dependency kinds, features and targets | Cargo.lock alone: lacks edge kinds |
| cargo-cyclonedx | 0.5.10 | Apache-2.0 | Rust CycloneDX | Official CycloneDX Cargo integration | Handwritten SBOM: more standards-maintenance work |
| uv pip compile --no-build | 0.9.8 | MIT OR Apache-2.0 | Python resolution fallback | Avoids building sdists; preserves via annotations | pip install + pipdeptree: executes target installation code |
| cyclonedx-bom / cyclonedx-py | 9.0.0 | Apache-2.0 | Python CycloneDX | Official generator accepts requirements | Environment inventory: requires installing target dependencies |
| Syft | 1.57.2 | Apache-2.0 | Image inventory and SPDX 2.3 | Reads image content without execution | Trivy: reserved for later vulnerability work |
| CycloneDX CLI | 0.33.1 | Apache-2.0 | CycloneDX validation/merge | Standards validation independent of graph model | JSON syntax only: does not prove standards compliance |
| spdx-tools / pyspdxtools | 0.8.5 | Apache-2.0 | SPDX validation | Semantic and schema checks | JSON parser alone: no SPDX validation |
| NetworkX | 3.7 | BSD-3-Clause | Directed dependency graph | Paths, ancestors and depth | Custom traversal engine: unnecessary maintenance |
| SQLite | Python bundled; runtime version recorded in tools.lock.md | Public domain | Persistent graph and evidence | Zero-service transactional store | Neo4j: deployment cost at this scale |
| pyvis | 0.3.2 | BSD-3-Clause | Static interactive graph HTML | Shareable artifact without app server | Streamlit: application UI belongs to a later checkpoint |
| PyYAML | 6.0.4 | MIT | Target configuration | Safe YAML loader | Custom config parser: unnecessary complexity |
| pytest | 9.2.0 | MIT | Unit and integration checks | Fixtures and readable assertions | unittest: more fixture boilerplate |
| ruff | 0.17.6 | MIT | Lint and formatting | Single fast tool | Separate flake8/isort/black: extra configuration |
| Docker Engine / CLI | 28.4.0 | Apache-2.0 | Pull/create/copy image files | Existing Docker Desktop Linux engine | Running images: unnecessary execution of target code |
| Git | 2.49.0.windows.1 | GPL-2.0-only | Immutable repository acquisition | Commit-addressed provenance | ZIP downloads alone: weaker Git provenance |
| GitHub Actions | SHA-pinned workflow actions | MIT (selected actions) | Test/lint CI | Existing team repository integration | Jenkins: extra service to operate |
| xAI client (deferred) | Not installed or called | SDK: Apache-2.0; API: commercial service | Future LLM factory stub only | Planned OpenAI-compatible endpoint | LiteLLM: unnecessary additional abstraction |

The proposed future model name `grok-4.7` is an unverified configuration proposal,
not a Checkpoint 1 dependency. Model availability and structured outputs must be
verified before implementing Checkpoint 2. No LLM SDK or API call is needed here.

## Reproducibility and verification

Python direct dependencies are exact pins in `pyproject.toml`; full resolution and
artifact hashes are in `uv.lock`. Scanner release binaries are pinned in
`tools.lock.md`. Windows Cargo CycloneDX uses the official release binary;
source installation, if used elsewhere, must be `cargo install --locked
--version 0.5.10 cargo-cyclonedx` (the tool, never scanned target code).

Installed package metadata supplied Python license/version checks. Official sources:

- [Rust installation](https://doc.rust-lang.org/stable/book/ch01-01-installation.html)
- [Cargo CycloneDX](https://github.com/CycloneDX/cyclonedx-rust-cargo)
- [CycloneDX Python](https://github.com/CycloneDX/cyclonedx-python)
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli)
- [Syft](https://github.com/anchore/syft)
- [SPDX tools](https://github.com/spdx/tools-python)

Cargo configuration and toolchain override files in acquired repositories must
not control host execution. The scanner must reject unsafe command overrides
before invoking resolution tools. `--no-build` is mandatory for Python fallback.
