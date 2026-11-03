"""No-network synthetic signed-device-key fixture helper checks."""

import base64
from copy import deepcopy
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.test import SimpleTestCase

from .vendor_fixtures.synapse_probe import device_bundle


class SynapseFixtureHelperTests(SimpleTestCase):
    def test_device_bundle_is_genuinely_signed_public_material(self):
        user, device = "@synthetic:fixture.invalid", "FIXTURE_A"
        bundle = device_bundle(user, device)
        key = bundle["keys"]["ed25519:" + device]
        signature = bundle["signatures"][user]["ed25519:" + device]
        signer = Ed25519PublicKey.from_public_bytes(base64.b64decode(key + "=="))
        unsigned = deepcopy(bundle)
        del unsigned["signatures"]
        canonical = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        signer.verify(base64.b64decode(signature + "=="), canonical)
        self.assertEqual(
            len(base64.b64decode(bundle["keys"]["curve25519:" + device] + "==")), 32
        )
        self.assertEqual(
            set(bundle), {"user_id", "device_id", "algorithms", "keys", "signatures"}
        )
        with self.assertRaises(InvalidSignature):
            signer.verify(base64.b64decode(signature + "=="), canonical + b"tampered")
