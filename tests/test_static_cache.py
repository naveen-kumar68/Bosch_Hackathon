import json

from guardian.detect import static_tools
from guardian.evidence import Recorder


def test_semgrep_cache_binds_source_rules_and_image(tmp_path, monkeypatch):
    source = tmp_path / "artifact"
    source.mkdir()
    (source / "build.rs").write_text('TcpStream::connect("127.0.0.1:9");')
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test.yaml").write_text("rules: []")
    recorder = Recorder(tmp_path / "out", root=tmp_path)
    commands = []

    def run(recorder, command, **kwargs):
        commands.append(command)
        assert "--network" in command and "none" in command
        payload = {"results": [], "errors": []}
        evidence = recorder.capture(
            json.dumps(payload).encode(),
            tool="docker",
            version="fixture",
            command=command,
            cwd=tmp_path,
        )
        return payload, evidence

    monkeypatch.setattr(static_tools, "run_json", run)
    first, evidence = static_tools.semgrep(source, rules, recorder)
    second, cached = static_tools.semgrep(source, rules, recorder)
    assert first == second and evidence == cached and len(commands) == 1
    (source / "build.rs").write_text("std::env::vars();")
    static_tools.semgrep(source, rules, recorder)
    assert len(commands) == 2
    (rules / "test.yaml").write_text("rules: []\n# changed")
    static_tools.semgrep(source, rules, recorder)
    assert len(commands) == 3
