"""Explicit host-side phases for OWN local GitLab fixture only.

No production fallback, generic scripts API or Docker socket is exposed. Source
bootstrap files and secret outputs live solely on the run's private tmpfs.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import time


def read_immutable_source(containers, image, path):
    """Only two immutable public startup files, always in owned lifecycle."""
    roles = {
        "/opt/gitlab/embedded/bin/runsvdir-start": "source-runsvdir",
        "/assets/sshd_config": "source-sshd",
    }
    if containers.service != "gitlab" or path not in roles:
        raise ValueError("fixture_source_not_allowed")
    args = [
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--cpus",
        "0.5",
        "--memory",
        "128m",
        "--memory-swap",
        "128m",
        "--pids-limit",
        "64",
        "--entrypoint",
        "/opt/gitlab/embedded/bin/ruby",
        image,
        "-e",
        "STDOUT.write(File.binread(" + json.dumps(path) + "))",
    ]
    result = containers.launch(roles[path], args, detached=False, timeout=30)
    if result.returncode:
        raise RuntimeError("fixture_immutable_source_read_failed")
    return result.stdout


class GitlabHostPhases:
    def __init__(self, runtime, server_id, namespace, containers, image):
        if not re.fullmatch(r"[0-9a-f]{64}", server_id) or not re.fullmatch(
            r"[0-9a-f]{64}", namespace
        ):
            raise ValueError("fixture_container_id_required")
        if containers.service != "gitlab":
            raise ValueError("fixture_service_required")
        self.runtime, self.out = Path(runtime), Path(runtime) / "out"
        self.server_id, self.namespace, self.containers, self.image = (
            server_id,
            namespace,
            containers,
            image,
        )
        self.uid, self.gid = os.getuid(), os.getgid()
        self.completed = []
        self.ssh_baseline = {}

    def command(self, args, timeout=30):
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("fixture_host_command_failed")
        return result

    def seed(self, payload):
        selected = {
            label: {key: payload[label][key] for key in ["id", "marker"]}
            for label in ["a", "b"]
        }
        for value in selected.values():
            if not re.fullmatch(r"[1-9][0-9]*", value["id"]):
                raise ValueError("fixture_native_id_invalid")
            if not value["marker"].startswith("user-admin-v1:"):
                raise ValueError("fixture_owner_marker_required")
        identities = self.out / "seed-identities.json"
        identities.write_text(json.dumps(selected))
        identities.chmod(0o444)
        source = """require 'json'
require 'securerandom'
rows=JSON.parse(File.read('/fixture-out/seed-identities.json'))
rows.each do |label,row|
 user=User.find(row.fetch('id').to_i)
 raise 'fixture_ownership_required' unless !user.admin? && user.note==row.fetch('marker')
 password=SecureRandom.urlsafe_base64(32)+'aA9!'
 user.password=password
 user.password_confirmation=password
 user.password_automatically_set=false if user.respond_to?(:password_automatically_set=)
 user.password_expires_at=nil if user.respond_to?(:password_expires_at=)
 user.save!
 File.open('/fixture-out/password-'+label,File::WRONLY|File::CREAT|File::EXCL,0600){|file|file.write(password)}
end
"""
        script = self.out / "seed-users.rb"
        script.write_text(source)
        script.chmod(0o444)
        self.command(
            ["docker", "exec", self.server_id, "/bin/chown", "git:git", "/fixture-out"]
        )
        try:
            self.command(
                [
                    "docker",
                    "exec",
                    self.server_id,
                    "/opt/gitlab/bin/gitlab-rails",
                    "runner",
                    "/fixture-out/seed-users.rb",
                ],
                100,
            )
        finally:
            self.command(
                [
                    "docker",
                    "exec",
                    self.server_id,
                    "/bin/chown",
                    "-R",
                    f"{self.uid}:{self.gid}",
                    "/fixture-out",
                ]
            )

    def ssh_refs(self, phase, label, repository):
        if label not in {"a", "b"} or not re.fullmatch(
            r"ua_[0-9a-f]{24}/synthetic-repository", repository
        ):
            raise ValueError("fixture_repository_invalid")
        ssh = f"ssh -i /keys/{label} -p 19022 -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/keys/known_hosts -o ConnectTimeout=5 -o LogLevel=ERROR"
        args = [
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--network",
            "container:" + self.namespace,
            "--user",
            f"{self.uid}:{self.gid}",
            "--cpus",
            "0.5",
            "--memory",
            "96m",
            "--memory-swap",
            "96m",
            "--pids-limit",
            "64",
            "--tmpfs",
            "/tmp:rw,nosuid,noexec,size=8m",
            "--mount",
            f"type=bind,src={self.runtime / 'keys'},dst=/keys,readonly",
            "-e",
            "HOME=/tmp",
            "-e",
            "GIT_TERMINAL_PROMPT=0",
            "-e",
            "GIT_CONFIG_NOSYSTEM=1",
            "-e",
            "GIT_SSH_COMMAND=" + ssh,
            "--entrypoint",
            "/opt/gitlab/embedded/bin/git",
            self.image,
            "ls-remote",
            "ssh://git@localhost:19022/" + repository + ".git",
        ]
        result = self.containers.launch(
            "ssh-" + phase + "-" + label, args, detached=False, timeout=30
        )
        values = []
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                match = re.fullmatch(
                    r"([0-9a-f]{40,64})\s+(HEAD|refs/[A-Za-z0-9/_.-]+)", line
                )
                if match:
                    values.append((match[1], match[2]))
            if not values:
                raise RuntimeError("fixture_ssh_refs_missing")
        denied = result.returncode != 0 and any(
            word in result.stderr.lower()
            for word in [
                "permission denied",
                "account is blocked",
                "account has been blocked",
                "account is banned",
                "access denied",
            ]
        )
        return result.returncode, tuple(sorted(values)), denied

    def duplicate_worker_done(self):
        source = """require 'json'
path='/var/log/gitlab/sidekiq/current'
rows=File.file?(path) ? File.readlines(path).last(4000) : []
rows=rows.filter_map{|line| begin JSON.parse(line);rescue JSON::ParserError;nil;end}
selected=rows.select{|row|row['class']=='AntiAbuse::BanDuplicateUsersWorker'}
puts JSON.generate({done:selected.any?{|row|row['job_status']=='done'},failed:selected.any?{|row|row['job_status']=='fail'}})
"""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = self.command(
                [
                    "docker",
                    "exec",
                    self.server_id,
                    "/opt/gitlab/embedded/bin/ruby",
                    "-e",
                    source,
                ],
                10,
            )
            value = json.loads(result.stdout)
            if value.get("failed") is True:
                raise RuntimeError("fixture_duplicate_worker_failed")
            if value.get("done") is True:
                return
            time.sleep(0.3)
        raise RuntimeError("fixture_duplicate_worker_not_observed")

    def handle(self, payload):
        phase = payload["phase"]
        order = ["seed", "baseline", "ban", "enable"]
        if len(self.completed) >= len(order) or phase != order[len(self.completed)]:
            raise ValueError("fixture_phase_order_invalid")
        if phase == "seed":
            self.seed(payload)
        else:
            results = {
                label: self.ssh_refs(phase, label, payload[label]["repository"])
                for label in ["a", "b"]
            }
            if phase == "baseline":
                if any(value[0] != 0 for value in results.values()):
                    raise RuntimeError("fixture_baseline_ssh_failed")
                self.ssh_baseline = results
            elif phase == "ban":
                if (
                    results["a"][0] == 0
                    or not results["a"][2]
                    or results["b"] != self.ssh_baseline["b"]
                ):
                    raise RuntimeError("fixture_banned_ssh_or_control_incorrect")
                self.duplicate_worker_done()
            elif results != self.ssh_baseline:
                raise RuntimeError("fixture_original_ssh_not_preserved")
        self.completed.append(phase)
        return {"phase": phase, "ok": True}
