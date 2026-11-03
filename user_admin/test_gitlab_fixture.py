"""No-network Git advertisement comparison for the local vendor fixture."""

from django.test import SimpleTestCase

from .vendor_fixtures.gitlab_probe import advertised_refs


def packet(payload):
    return f"{len(payload) + 4:04x}".encode() + payload


class GitlabFixtureHelperTests(SimpleTestCase):
    def test_session_capabilities_change_without_falsely_changing_refs(self):
        commit = b"a" * 40
        first = (
            packet(b"# service=git-upload-pack\n")
            + b"0000"
            + packet(commit + b" HEAD\x00session-id=first agent=git\n")
            + packet(commit + b" refs/heads/main\n")
            + b"0000"
        )
        second = first.replace(b"first", b"other")
        self.assertEqual(advertised_refs(first), advertised_refs(second))
        self.assertEqual(
            advertised_refs(first), (("a" * 40, "HEAD"), ("a" * 40, "refs/heads/main"))
        )
        self.assertNotEqual(
            advertised_refs(first.replace(b"a" * 40, b"b" * 40)), advertised_refs(first)
        )

    def test_truncated_packet_cannot_be_success(self):
        for payload in [b"0010too-short", b"0003", b"zzzz"]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                advertised_refs(payload)
