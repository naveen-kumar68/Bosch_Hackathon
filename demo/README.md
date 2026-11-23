# Safe planted scenario

Run `uv run python -m demo.prepare` after the pinned main target has been acquired.
It creates a local copy in ignored `demo/planted/`, verifies the original arrayref
archive against Cargo.lock, then applies controlled source/lockfile changes.
The build script's look-alike function is never called; its main is empty.
Nothing is built, executed or published. The fixture is data for static analysis.
