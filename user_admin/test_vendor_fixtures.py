"""No-server fixture safety and independent frozen query-signature vector."""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from .vendor_fixtures.minio_probe import presigned_get
from .vendor_fixtures.oidc import MARKER, runtime_directory


class VendorFixtureHelperTests(SimpleTestCase):
    def test_fixture_directory_requires_exact_explicit_synthetic_marker(self):
        with TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "fixture"
            runtime.mkdir()
            with self.assertRaises(FileNotFoundError):
                runtime_directory(str(runtime))
            (runtime / "marker").write_text("not-a-synthetic-fixture")
            with self.assertRaisesRegex(
                ValueError, "synthetic_fixture_marker_required"
            ):
                runtime_directory(str(runtime))
            (runtime / "marker").write_text(MARKER)
            self.assertEqual(runtime_directory(str(runtime)), runtime.resolve())
            renamed = Path(temporary) / "other"
            runtime.rename(renamed)
            with self.assertRaisesRegex(
                ValueError, "synthetic_fixture_marker_required"
            ):
                runtime_directory(str(renamed))

    def test_presigned_fixture_get_matches_independent_botocore_1_43_123_vector(self):
        # Frozen no-network S3SigV4QueryAuth oracle; these are PUBLIC fake keys.
        credentials = {
            "AccessKeyId": "SYNTHETIC-ACCESS",
            "SecretAccessKey": "synthetic-secret-only",
            "SessionToken": "synthetic/token+with=escapes",
        }
        target = presigned_get(
            credentials,
            "/synthetic-bucket/probe space.txt",
            datetime(2026, 11, 2, tzinfo=timezone.utc),
        )
        self.assertEqual(
            hashlib.sha256(target.encode()).hexdigest(),
            "99c35facb0c6e444a6587bfb90bc09c7b99fb1ba7f8afb1389518ece08e4cf67",
        )
        self.assertNotIn(credentials["SecretAccessKey"], target)
        self.assertIn("X-Amz-Expires=900", target)
