"""Versioned, bounded fixture evidence, never a configuration-created capability.

These records do NOT clear browser/OIDC or production activation gates. Runtime
observations stay unknown/unsupported; a profile never fabricates confirmation.
"""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class AcceptanceProfile:
    service: str
    code: str
    version: str
    image: str
    proof_sha256: str
    fixture_run: str
    scope: tuple[str, ...]
    prerequisites: tuple[str, ...]
    # Initial provisioning has its own acceptance; clearing lifecycle evidence
    # must never silently authorize the narrower (or vice versa) execution path.
    provisioning_blockers: tuple[str, ...] = (
        "provisioning_browser_not_accepted",
        "deployment_protocol_not_accepted",
        "production_activation_not_authorized",
    )
    blockers: tuple[str, ...] = (
        "browser_oidc_not_accepted",
        "deployment_protocol_not_accepted",
        "production_activation_not_authorized",
    )


PROFILES = MappingProxyType(
    {
        "gitlab-18.1.0-ce-ban-v1": AcceptanceProfile(
            "gitlab",
            "gitlab-18.1.0-ce-ban-v1",
            "18.1.0",
            "sha256:a68f3b3f27db3e5894784301714ecfadf03cf739f06420a741b349b38c0bdda0",
            "ead3342ee3b31cc1183aefe01a8577624f7ad20243a710fb1c1ea861f9ba11c8",
            "be60b21ce0a3445793445604ad4e3ff7",
            (
                "create_bind_ban_unban",
                "password_http_cookie_private_data",
                "pat_ssh_https_refs",
                "groups_ci_states_schedules_preserved",
                "not_ci_script_execution",
            ),
            (
                "self_managed_ce",
                "email_subaddress_restrictions_explicit_false",
                "exclusive_new_identity_authority",
            ),
        ),
        "synapse-1.164.1-lock-v1": AcceptanceProfile(
            "matrix",
            "synapse-1.164.1-lock-v1",
            "1.164.1",
            "sha256:ba2859095a5e592ba229b55381aceb23fd7152456eed1573143dfaef0ab11b7e",
            "f05d30f1099c362bb0e0d76851f92a6f1116148ff30d9b03eb507ba7e11b38f7",
            "fb5a36e9197a4a5a93654e17f8efaf8a",
            (
                "create_bind_lock_unlock",
                "password_sync_denial",
                "sessions_devices_rooms_signed_keys_preserved",
                "refresh_issuance_without_access_operator_accepted",
            ),
            ("exclusive_new_identity_authority", "no_deactivate_or_logout_all"),
        ),
        "minio-2023-05-18-owned-s3-v1": AcceptanceProfile(
            "minio",
            "minio-2023-05-18-owned-s3-v1",
            "RELEASE.2023-05-18T00-05-36Z",
            "sha256:1bafa2f68bad591fc47a0efce28da9345983ba23fc2b90e4e5a6917cb133aa53",
            "4354c60280672edf432c1e567193a1bf4812acf06e429579a26a1cf7edae511c",
            "3d594c1daf64407a8be50799b8a21253",
            (
                "own_uuid_bucket_policy",
                "sts_service_account_presigned_cookie_s3_denial",
                "s3_only_operator_accepted_not_issuance_revocation",
            ),
            (
                "standalone_no_site_replication",
                "claim_policy_only_no_role_plugin_bypass",
                "exclusive_new_policy_authority",
            ),
        ),
    }
)
