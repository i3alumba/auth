"""Synthetic documents only: these tests do not accept a MinIO capability."""

from copy import deepcopy
from uuid import UUID, uuid4

from django.test import SimpleTestCase

from .native.minio_policy import bucket_policy, policy_stamp, resource_name


class OwnedMinioPolicyTests(SimpleTestCase):
    def setUp(self):
        self.owner, self.operation = uuid4(), uuid4()

    def document(self, blocked=False):
        return bucket_policy(
            owner=self.owner, operation=self.operation, generation=3, blocked=blocked
        )

    def test_names_are_fixed_uuid_namespace_not_profile_or_browser_input(self):
        name = resource_name(self.owner)
        self.assertEqual(name, "ua-" + self.owner.hex)
        self.assertLessEqual(len(name), 63)
        self.assertRegex(name, r"^[a-z][a-z0-9-]+$")
        for value in [str(self.owner), "existing-bucket", None, True]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                resource_name(value)

    def test_allow_scope_is_only_the_one_new_bucket_without_admin_or_bucket_management(
        self,
    ):
        doc = self.document()
        arn = "arn:aws:s3:::" + resource_name(self.owner)
        for item in doc["Statement"]:
            self.assertEqual(item["Effect"], "Allow")
            self.assertIn(item["Resource"], [[arn], [arn + "/*"]])
            for action in item["Action"]:
                self.assertTrue(action.startswith("s3:"))
                self.assertNotIn("*", action)
                self.assertNotIn(
                    action,
                    [
                        "s3:ListAllMyBuckets",
                        "s3:CreateBucket",
                        "s3:DeleteBucket",
                        "s3:PutBucketPolicy",
                    ],
                )
        self.assertEqual(policy_stamp(doc, self.owner), (self.operation, 3, False))

    def test_block_is_only_an_explicit_deny_not_deletion_or_other_policy_edit(self):
        doc = self.document(True)
        self.assertEqual(len(doc["Statement"]), 1)
        item = doc["Statement"][0]
        self.assertEqual(item["Effect"], "Deny")
        self.assertEqual(item["Action"], ["s3:*"])
        arn = "arn:aws:s3:::" + resource_name(self.owner)
        self.assertEqual(item["Resource"], [arn, arn + "/*"])
        self.assertEqual(policy_stamp(doc, self.owner), (self.operation, 3, True))

    def test_foreign_owner_and_mismatched_statement_receipts_are_rejected(self):
        doc = self.document()
        with self.assertRaises(ValueError):
            policy_stamp(doc, uuid4())
        doc["Statement"][1]["Sid"] = doc["Statement"][1]["Sid"].replace(
            self.operation.hex, uuid4().hex
        )
        with self.assertRaises(ValueError):
            policy_stamp(doc, self.owner)

    def test_remote_serialization_order_and_singleton_sets_are_not_authority_changes(
        self,
    ):
        doc = self.document()
        doc["Statement"].reverse()
        for item in doc["Statement"]:
            item["Action"].reverse()
            item["Resource"] = item["Resource"][0]
        self.assertEqual(policy_stamp(doc, self.owner), (self.operation, 3, False))

    def test_marker_does_not_authorize_wider_or_modified_policies(self):
        baseline = self.document()
        variants = []
        for field, value in [
            ("Resource", ["*"]),
            ("Action", ["admin:*"]),
            ("Effect", "Deny"),
            ("Condition", {}),
        ]:
            doc = deepcopy(baseline)
            doc["Statement"][0][field] = value
            variants.append(doc)
        doc = deepcopy(baseline)
        doc["Statement"].append(
            {"Sid": "Foreign", "Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}
        )
        variants.append(doc)
        doc = deepcopy(baseline)
        doc["Statement"][0]["Action"].append(doc["Statement"][0]["Action"][0])
        variants.append(doc)
        for doc in variants:
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                policy_stamp(doc, self.owner)

    def test_malformed_documents_are_refused_without_evaluating_any_permissions(self):
        for doc in [
            None,
            [],
            {},
            {"Statement": None},
            {"Statement": [None]},
            {"Statement": [{"Sid": []}]},
            {"Statement": [{"Sid": "private-untrusted-body"}]},
        ]:
            with (
                self.subTest(doc=doc),
                self.assertRaisesRegex(ValueError, "policy_unverified"),
            ):
                policy_stamp(doc, self.owner)

    def test_invalid_generation_and_non_boolean_state_are_not_coerced(self):
        for generation in [True, 0, -1, "3", 2**63]:
            with self.subTest(generation=generation), self.assertRaises(ValueError):
                bucket_policy(
                    owner=self.owner,
                    operation=self.operation,
                    generation=generation,
                    blocked=False,
                )
        with self.assertRaises(ValueError):
            bucket_policy(
                owner=self.owner,
                operation=self.operation,
                generation=1,
                blocked="false",
            )
