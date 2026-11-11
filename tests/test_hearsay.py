import json
import os
import unittest

from hearsay.core import extract_atoms, load_trace, analyze
from hearsay.cli import main

HERE = os.path.dirname(__file__)
EXAMPLE = os.path.join(HERE, "..", "examples", "incident.jsonl")


def trace(*events):
    return load_trace(json.dumps(e) for e in events)


def kinds(findings):
    return sorted((f.kind, f.agent, f.atom) for f in findings)


class Extract(unittest.TestCase):
    def test_atoms(self):
        a = extract_atoms("p99 2400ms, CVE-2026-1234 see https://x.io/a/ and deploy/app.yaml v1.2.3 sha 4f9c2ab")
        self.assertEqual(a["2400ms"], "number")
        self.assertEqual(a["cve-2026-1234"], "cve")
        self.assertEqual(a["https://x.io/a"], "url")
        self.assertEqual(a["deploy/app.yaml"], "path")
        self.assertEqual(a["v1.2.3"], "version")
        self.assertEqual(a["4f9c2ab"], "hash")

    def test_trivial_numbers_skipped(self):
        self.assertEqual(extract_atoms("step 3 of 5"), {})

    def test_backtick_code(self):
        self.assertIn("retry_budget", extract_atoms("set `retry_budget` now"))


class Analyze(unittest.TestCase):
    def test_grounded_is_clean(self):
        f = analyze(trace(
            {"agent": "a", "type": "tool_result", "content": "latency 950ms"},
            {"agent": "a", "type": "message", "content": "latency is 950ms"},
        ))
        self.assertEqual(f, [])

    def test_user_grounds_everyone(self):
        f = analyze(trace(
            {"agent": "user", "type": "user", "content": "deploy v2.4.1"},
            {"agent": "a", "type": "message", "content": "deploying v2.4.1"},
            {"agent": "b", "type": "tool_call", "tool": "deploy", "content": {"v": "v2.4.1"}},
        ))
        self.assertEqual(f, [])

    def test_rumor_then_relay_then_action(self):
        f = analyze(trace(
            {"agent": "a", "type": "message", "content": "the bad build is 9e8d7c6"},
            {"agent": "b", "type": "message", "content": "reverting 9e8d7c6"},
            {"agent": "b", "type": "tool_call", "tool": "git.revert", "content": {"sha": "9e8d7c6"}},
        ))
        self.assertEqual(kinds(f), [
            ("acted-on-rumor", "b", "9e8d7c6"),
            ("hearsay", "b", "9e8d7c6"),
            ("rumor", "a", "9e8d7c6"),
        ])
        self.assertEqual([x.severity for x in f if x.kind == "acted-on-rumor"], ["high"])

    def test_hearsay_with_origin_is_low_and_action_medium(self):
        f = analyze(trace(
            {"agent": "a", "type": "tool_result", "content": "found CVE-2025-1111"},
            {"agent": "a", "type": "message", "content": "CVE-2025-1111 applies"},
            {"agent": "b", "type": "message", "content": "patching CVE-2025-1111"},
            {"agent": "b", "type": "tool_call", "tool": "ticket", "content": "CVE-2025-1111"},
        ))
        self.assertEqual([(x.kind, x.severity) for x in f],
                         [("hearsay", "low"), ("acted-on-hearsay", "medium")])
        self.assertEqual(f[0].origin, "tool_result:a@1")

    def test_shared_results_mode(self):
        evs = [
            {"agent": "a", "type": "tool_result", "content": "disk 87%"},
            {"agent": "b", "type": "message", "content": "disk is at 87%"},
        ]
        self.assertEqual(len(analyze(trace(*evs))), 1)
        self.assertEqual(analyze(trace(*evs), shared_results=True), [])

    def test_agent_self_grounding_later(self):
        f = analyze(trace(
            {"agent": "a", "type": "message", "content": "port 8443 maybe"},
            {"agent": "b", "type": "tool_result", "content": "listening on 8443"},
            {"agent": "b", "type": "message", "content": "confirmed 8443"},
            {"agent": "b", "type": "tool_call", "tool": "fw.open", "content": {"port": 8443}},
        ))
        self.assertEqual(kinds(f), [("rumor", "a", "8443")])

    def test_own_fresh_arg_not_flagged(self):
        f = analyze(trace({"agent": "a", "type": "tool_call", "tool": "x", "content": {"n": 4242}}))
        self.assertEqual(f, [])


class CLI(unittest.TestCase):
    def test_example_fail_gate(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([EXAMPLE, "--fail-on", "acted-on-rumor"])
        self.assertEqual(rc, 1)
        self.assertIn("acted-on-rumor", buf.getvalue())

    def test_json_and_min_severity(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([EXAMPLE, "--format", "json", "--min-severity", "high"])
        data = json.loads(buf.getvalue())
        self.assertEqual(rc, 0)
        self.assertTrue(all(f["severity"] == "high" for f in data["findings"]))
        self.assertEqual(data["summary"], {"acted-on-rumor": 2})


if __name__ == "__main__":
    unittest.main()
