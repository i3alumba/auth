"""Frozen no-network botocore 1.43.123 signing vectors; synthetic credentials."""

from datetime import datetime, timezone

from django.test import SimpleTestCase

from .native.sigv4 import sign_s3

NOW = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


class NativeS3SigningTests(SimpleTestCase):
    def sign(self, method="GET", target="/", body=b"", headers=None, **kwargs):
        data = dict(
            access_key="AKIDEXAMPLE",
            secret_key="synthetic-signing-secret-for-test-only",
            authority="vendor.invalid:9443",
            method=method,
            target=target,
            body=body,
            now=NOW,
            headers=headers,
        )
        data.update(kwargs)
        return sign_s3(**data)

    def test_matches_independent_sdk_reference_vectors_for_bucket_and_policy_requests(
        self,
    ):
        cases = [
            (
                "PUT",
                "/ua-0123456789abcdef0123456789abcdef",
                b"",
                {},
                "068c821a21e9f805513d69d9ce0612b82126540506de95e71c8bf6104702d2ee",
            ),
            (
                "PUT",
                "/minio/admin/v3/add-canned-policy?name=ua-example",
                b'{"Version":"2012-10-17","Statement":[]}',
                {"Content-Type": "application/json"},
                "3809c40e52cc4879d6625266716bd30c5156a54df797a0dcd04e3e4358e7ebea",
            ),
            (
                "GET",
                "/minio/admin/v3/info?z=last&a=first",
                b"",
                {},
                "76878f3da61f1bdf52f04eac91e6a705bd4296e8242ea5b1807cb6a3d75c2afd",
            ),
            (
                "GET",
                "/test.txt",
                b"",
                {"Range": "bytes=0-9"},
                "d591bc7e218e93ba1398ac1e1143f3a981e8d4348534828ff8bcb1a66b3ce2ff",
            ),
        ]
        for method, target, body, headers, expected in cases:
            with self.subTest(target=target):
                result = self.sign(method, target, body, headers)
                self.assertEqual(
                    result["authorization"].split("Signature=")[1], expected
                )
                self.assertEqual(result["host"], "vendor.invalid:9443")
                self.assertEqual(result["x-amz-date"], "20250102T030405Z")
                self.assertNotIn("synthetic-signing-secret", result["authorization"])

    def test_query_order_is_canonical_and_body_bytes_change_signature(self):
        self.assertEqual(
            self.sign(target="/?z=last&a=first"), self.sign(target="/?a=first&z=last")
        )
        self.assertNotEqual(
            self.sign("PUT", "/", b"one")["authorization"],
            self.sign("PUT", "/", b"two")["authorization"],
        )

    def test_ambiguous_paths_or_query_and_header_injection_are_refused(self):
        for target in [
            "https://other.invalid/",
            "//other.invalid/",
            "/../bucket",
            "/encoded%2Fpath",
            "/?name=bad+space",
            "/?name=%zz",
            "/?name=%00",
            "/#fragment",
        ]:
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(ValueError, "^invalid_s3_signing_request$"),
            ):
                self.sign(target=target)
        for headers in [
            {"Authorization": "secret"},
            {"Host": "other.invalid"},
            {"Content-Type": "secret\r\n"},
            {"Content-Type": "one", "content-type": "two"},
        ]:
            with (
                self.subTest(headers=headers),
                self.assertRaisesRegex(ValueError, "^invalid_s3_signing_request$"),
            ):
                self.sign(headers=headers)

    def test_invalid_configuration_does_not_echo_private_values(self):
        for kwargs in [
            {"access_key": "private/key"},
            {"secret_key": "short"},
            {"authority": "user:private@host"},
            {"region": "invalid/region"},
            {"now": datetime(2025, 1, 1)},
            {"body": "private-body-not-bytes"},
        ]:
            with (
                self.subTest(kwargs=kwargs),
                self.assertRaisesRegex(ValueError, "^invalid_s3_signing_request$"),
            ):
                self.sign(**kwargs)
