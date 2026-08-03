#!/usr/bin/env python3
"""The corpus is the contract.

Two halves, and the second matters more:

  vulnerable.php  every defect the tool claims to find must be found
  hardened.php    the same plugin written correctly must produce nothing

A scanner that flags correct code gets muted within a day, so a false positive
on hardened.php is treated as a failure exactly like a miss on vulnerable.php.

    python3 -m unittest discover -s tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wpauthz.analyze import analyse_file, rank  # noqa: E402
from wpauthz.entrypoints import scan_file  # noqa: E402
from wpauthz.guards import classify, sinks  # noqa: E402
from wpauthz.index import build as build_index  # noqa: E402
from wpauthz.php import blank_noncode, calls, functions, literal  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def findings_for(name: str, with_index: bool = False):
    path = FIXTURES / name
    source = path.read_text(encoding="utf-8")
    index = build_index(FIXTURES) if with_index else None
    return rank(analyse_file(path, source, scan_file(path, source), index))


def entries_for(name: str):
    path = FIXTURES / name
    return scan_file(path, path.read_text(encoding="utf-8"))


class TestPhpModel(unittest.TestCase):
    def test_comment_contents_are_blanked(self):
        source = "<?php /* current_user_can('manage_options') */ $x = 1;"
        self.assertNotIn("current_user_can", blank_noncode(source))

    def test_string_contents_are_blanked_but_offsets_hold(self):
        source = "<?php $a = 'current_user_can'; $b = 2;"
        blanked = blank_noncode(source)
        self.assertNotIn("current_user_can", blanked)
        self.assertEqual(len(blanked), len(source))

    def test_calls_inside_comments_are_not_reported(self):
        source = "<?php // update_option('a', 'b');\n$x = 1;"
        self.assertEqual(list(calls("update_option", source)), [])

    def test_function_body_survives_nested_braces(self):
        source = "<?php function f() { if (true) { $a = 1; } $b = 2; } function g() { $c = 3; }"
        found = {fn.name: fn for fn in functions(source)}
        self.assertIn("f", found)
        self.assertIn("g", found)
        self.assertIn("$b = 2", found["f"].body(source))
        self.assertNotIn("$c = 3", found["f"].body(source))

    def test_brace_inside_string_does_not_truncate_a_body(self):
        source = '<?php function f() { $a = "}"; $b = 2; } function g() { $c = 3; }'
        found = {fn.name: fn for fn in functions(source)}
        self.assertIn("$b = 2", found["f"].body(source))

    def test_argument_with_nested_parens_is_kept_whole(self):
        source = "<?php add_action('wp_ajax_x', array($this, 'h'), 10, absint(1));"
        call = next(calls("add_action", source))
        self.assertEqual(call.args[1], "array($this, 'h')")

    def test_interpolated_string_is_not_a_literal(self):
        self.assertIsNone(literal('"wp_ajax_$action"'))
        self.assertEqual(literal("'wp_ajax_save'"), "wp_ajax_save")

    def test_heredoc_contents_are_blanked(self):
        source = "<?php $sql = <<<SQL\nupdate_option('x','y')\nSQL;\n$a = 1;"
        self.assertEqual(list(calls("update_option", source)), [])


class TestEntryPointDiscovery(unittest.TestCase):
    def test_finds_every_entry_point_kind(self):
        kinds = {entry.kind for entry in entries_for("vulnerable.php")}
        for expected in ("ajax_nopriv", "ajax", "lifecycle", "rest", "meta"):
            self.assertIn(expected, kinds, f"missed entry point kind: {expected}")

    def test_admin_init_is_treated_as_unauthenticated(self):
        entry = next(e for e in entries_for("vulnerable.php") if e.hook == "admin_init")
        self.assertEqual(entry.reach, 0)

    def test_rest_routes_are_split_per_handler(self):
        rest = [e for e in entries_for("vulnerable.php") if e.kind == "rest"]
        self.assertEqual(len(rest), 3, f"expected 3 REST routes, got {[e.hook for e in rest]}")

    def test_callback_array_syntax_resolves_to_a_method(self):
        entry = next(e for e in entries_for("vulnerable.php") if e.hook == "wp_ajax_nopriv_demo_save")
        self.assertTrue(entry.callback.endswith("save_settings"))
        self.assertIsNotNone(entry.resolved)


class TestGuardClassification(unittest.TestCase):
    def test_nonce_is_not_a_capability_check(self):
        guards, _ = classify("check_ajax_referer('a','n'); update_option('x', $_POST['y']);")
        self.assertTrue(guards)
        self.assertFalse(any(guard.is_capability for guard in guards))
        self.assertTrue(any(guard.is_nonce for guard in guards))

    def test_is_admin_is_reported_as_a_pseudo_guard(self):
        _, notes = classify("if (is_admin()) { update_option('x', 1); }")
        self.assertTrue(any("is_admin" in note for note in notes))

    def test_meta_capability_carries_an_object_argument(self):
        guards, _ = classify("current_user_can('edit_post', $id);")
        self.assertTrue(guards[0].has_object_argument)
        self.assertTrue(guards[0].is_meta)

    def test_primitive_capability_has_no_object_argument(self):
        guards, _ = classify("current_user_can('edit_posts');")
        self.assertFalse(guards[0].has_object_argument)

    def test_tainted_object_id_is_detected(self):
        found = sinks("update_post_meta($_POST['post_id'], 'k', 'v');")
        write = next(s for s in found if s.function == "update_post_meta")
        self.assertTrue(write.tainted_object_id)

    def test_untainted_object_id_is_not_flagged(self):
        found = sinks("update_post_meta($post_id, 'k', 'v');")
        write = next(s for s in found if s.function == "update_post_meta")
        self.assertFalse(write.tainted_object_id)


class TestVulnerableFixture(unittest.TestCase):
    def setUp(self):
        self.findings = findings_for("vulnerable.php")
        self.titles = " | ".join(f.title for f in self.findings)

    def test_unauthenticated_write_is_high(self):
        match = [f for f in self.findings
                 if f.entry.hook == "wp_ajax_nopriv_demo_save"]
        self.assertTrue(match, f"missed the nopriv write; got: {self.titles}")
        self.assertEqual(match[0].severity, "high")
        self.assertEqual(match[0].tier, "unauth")
        self.assertEqual(match[0].cwe, "CWE-862")

    def test_nonce_only_handler_is_reported(self):
        match = [f for f in self.findings if f.entry.hook == "wp_ajax_demo_nonce_only"]
        self.assertTrue(match, f"a nonce was accepted as authorization; got: {self.titles}")
        self.assertEqual(match[0].tier, "subscriber")
        self.assertTrue(any("CSRF" in line for line in match[0].evidence))

    def test_primitive_capability_over_supplied_object_is_cwe_863(self):
        match = [f for f in self.findings if f.entry.hook == "wp_ajax_demo_meta"]
        self.assertTrue(match, f"missed the primitive-vs-meta capability case; got: {self.titles}")
        self.assertEqual(match[0].cwe, "CWE-863")

    def test_admin_init_write_is_unauthenticated(self):
        match = [f for f in self.findings if f.entry.hook == "admin_init"]
        self.assertTrue(match, f"missed the admin_init case; got: {self.titles}")
        self.assertEqual(match[0].tier, "unauth")

    def test_rest_route_without_permission_callback(self):
        match = [f for f in self.findings if "import" in f.entry.hook]
        self.assertTrue(match, f"missed the missing permission_callback; got: {self.titles}")
        self.assertEqual(match[0].severity, "high")

    def test_public_state_changing_rest_route(self):
        match = [f for f in self.findings if "reset" in f.entry.hook]
        self.assertTrue(match, f"missed the public write route; got: {self.titles}")
        self.assertEqual(match[0].severity, "high")

    def test_permissive_meta_auth_callback(self):
        match = [f for f in self.findings if f.entry.kind == "meta"]
        self.assertTrue(match, f"missed the permissive auth_callback; got: {self.titles}")
    def test_meta_severity_follows_the_key_name(self):
        meta = {f.entry.hook.rsplit(":", 1)[-1]: f.severity
                for f in self.findings if f.entry.kind == "meta"}
        self.assertEqual(meta.get("_demo_licence_key"), "high",
                         "a licence-key meta write should rank high")
        self.assertEqual(meta.get("_demo_changed"), "medium",
                         "a boolean dirty-flag should not rank high")

    def test_public_read_route_is_not_reported(self):
        self.assertFalse(
            [f for f in self.findings if "status" in f.entry.hook],
            "a public GET route with no writes must not be a finding",
        )

    def test_capability_named_only_in_a_comment_does_not_protect(self):
        # The fixture's docblock mentions current_user_can('manage_options').
        self.assertTrue(self.findings, "comment text was treated as a guard")


class TestHardenedFixture(unittest.TestCase):
    def test_correct_plugin_produces_no_findings(self):
        findings = findings_for("hardened.php")
        self.assertEqual(
            [],
            findings,
            "false positives on correct code: "
            + " | ".join(f"{f.entry.hook}: {f.title}" for f in findings),
        )

    def test_guard_in_a_helper_is_inherited(self):
        findings = findings_for("hardened.php")
        self.assertFalse(
            [f for f in findings if f.entry.hook == "admin_init"],
            "a capability check delegated to a helper was not inherited",
        )


class TestCrossFileGuards(unittest.TestCase):
    """Regression for a false positive found against a real 2M-install plugin.

    Its AJAX handlers were guarded by a plugin-defined wrapper around
    current_user_can() that lived in another file. Without cross-file
    resolution, correct code was reported as critical.
    """

    def test_wrapper_in_another_file_counts_as_a_guard(self):
        findings = findings_for("wrapped_guard.php", with_index=True)
        self.assertEqual(
            [],
            findings,
            "a capability check wrapped in another file was not recognised: "
            + " | ".join(f.title for f in findings),
        )

    def test_without_the_index_the_same_code_is_reported(self):
        # Documents exactly what the index buys, so a regression here is loud.
        self.assertTrue(
            findings_for("wrapped_guard.php", with_index=False),
            "fixture no longer exercises the cross-file case",
        )

    def test_index_does_not_suppress_a_genuinely_unguarded_handler(self):
        findings = findings_for("vulnerable.php", with_index=True)
        self.assertTrue(
            [f for f in findings if f.entry.hook == "wp_ajax_nopriv_demo_save"],
            "cross-file inlining swallowed a real finding",
        )

    def test_only_guard_like_helpers_are_inlined(self):
        index = build_index(FIXTURES)
        self.assertIn("demo_current_user_can_admin", index.guard_names)
        # A helper with no capability call must not be treated as a guard.
        self.assertNotIn("rest_status", index.guard_names)


class TestRanking(unittest.TestCase):
    def test_high_severity_sorts_before_medium(self):
        findings = findings_for("vulnerable.php")
        severities = [f.severity for f in findings]
        self.assertEqual(severities, sorted(severities, key=lambda s: ["high", "medium", "low", "info"].index(s)))

    def test_unauthenticated_sorts_before_authenticated_at_equal_severity(self):
        findings = [f for f in findings_for("vulnerable.php") if f.severity == "high"]
        tiers = [f.tier for f in findings]
        self.assertEqual(tiers[0], "unauth")


if __name__ == "__main__":
    unittest.main()
