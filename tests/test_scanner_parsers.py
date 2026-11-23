from guardian.detect.vulns import deduplicate, parse_audit, parse_osv
from guardian.models import Component


def test_native_union_and_warning_flags():
    component = Component(
        purl="pkg:cargo/example@1",
        name="example",
        version="1",
        ecosystem="cargo",
        source="crates.io",
        evidence_ids=["scan"],
    )
    osv = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "example", "version": "1", "ecosystem": "crates.io"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-1",
                                "aliases": ["CVE-1", "RUSTSEC-1"],
                                "affected": [
                                    {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2"}]}]}
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    audit = {
        "vulnerabilities": {
            "list": [
                {
                    "advisory": {"id": "RUSTSEC-1", "aliases": ["CVE-1"]},
                    "versions": {"patched": [">=2"]},
                    "package": {"name": "example", "version": "1"},
                }
            ]
        },
        "warnings": {
            "unsound": [
                {"advisory": {"id": "RUSTSEC-2"}, "package": {"name": "example", "version": "1"}}
            ]
        },
    }
    merged = deduplicate(
        parse_osv(osv, [component], "osv") + parse_audit(audit, [component], "audit")
    )
    assert len(merged) == 2
    assert next(v for v in merged if v.id == "CVE-1").sources == ["cargo-audit", "osv"]
    assert next(v for v in merged if v.id == "RUSTSEC-2").flags == ["unsound"]
