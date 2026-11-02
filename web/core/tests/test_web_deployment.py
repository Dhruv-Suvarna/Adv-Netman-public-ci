"""V2 Phase 1: repository-owned web deployment templates (Gunicorn / systemd / Apache / cloudflared) stay safe."""

import os
import re
import subprocess
import sys
from pathlib import Path

import yaml
from django.conf import settings
from django.test import SimpleTestCase

DEPLOY = Path(settings.REPO_ROOT) / "deploy"
_CURRENT_USER = __import__("pwd").getpwuid(os.getuid()).pw_name      # the rendering tests must work on any host, not only the lab's
# A literal key VALUE (not a placeholder such as <...> or a shell expansion such as ${SECRET} / .*).
SECRET_SHAPES = re.compile(r"(?i)(SECRET_KEY=[A-Za-z0-9_\-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY|AccountTag|TunnelSecret|eyJhIjoi)")


class DeploymentTemplateTests(SimpleTestCase):
    def read(self, rel):
        return (DEPLOY / rel).read_text()

    def test_no_secret_material_in_templates(self):
        for path in DEPLOY.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                self.assertIsNone(SECRET_SHAPES.search(path.read_text()), path)

    def test_gunicorn_binds_loopback_only(self):
        namespace = {}
        exec(compile(self.read("gunicorn/gunicorn.conf.py"), "gunicorn.conf.py", "exec"), namespace)  # noqa: S102
        self.assertTrue(namespace["bind"].startswith("127.0.0.1:"))
        self.assertNotIn("%(q)s", namespace["access_log_format"])  # never the query string

    def test_systemd_unit_reads_secrets_from_protected_env_file(self):
        unit = self.read("systemd/nmas-web.service")
        self.assertIn("EnvironmentFile=/etc/nmas/nmas-web.env", unit)
        self.assertIn("gunicorn", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertNotRegex(unit, r"Environment=DJANGO_SECRET_KEY")
        exec_start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
        self.assertNotIn("runserver", exec_start)

    def test_apache_vhosts_are_loopback_and_overwrite_forwarded_proto(self):
        vhosts = self.read("apache/nmas.conf")
        common = self.read("apache/nmas-common.conf")
        self.assertIn("Listen 127.0.0.1:8081", vhosts)
        self.assertNotRegex(vhosts, r"Listen (0\.0\.0\.0|\*|80\b)")
        self.assertEqual(vhosts.count('RequestHeader set X-Forwarded-Proto "http"'), 1)
        self.assertEqual(vhosts.count('RequestHeader set X-Forwarded-Proto "https"'), 1)
        self.assertIn("RequestHeader unset X-Forwarded-Proto early", common)
        self.assertIn("ProxyPass / http://127.0.0.1:8002/", common)
        self.assertIn("ProxyPass /static/ !", common)
        self.assertNotIn("%q", common)  # access log never records query strings

    def test_cloudflared_ingress_is_website_only(self):
        config = yaml.safe_load(self.read("cloudflared/config.yml.example"))
        ingress = config["ingress"]
        self.assertEqual(len(ingress), 2)
        self.assertEqual(ingress[0]["service"], "http://127.0.0.1:8081")
        self.assertEqual(ingress[-1], {"service": "http_status:404"})
        self.assertTrue(config["tunnel"].startswith("<"), "placeholder only")

    def test_env_example_has_placeholders_only(self):
        env = self.read("env/nmas-web.env.example")
        self.assertIn("DJANGO_SECRET_KEY=<generated-by-installer>", env)
        self.assertIn("DJANGO_DEBUG=false", env)
        self.assertIn("NMAS_APP_MFA_REQUIRED=true", env)

    def test_scripts_are_valid_bash(self):
        for script in (DEPLOY / "scripts").glob("*.sh"):
            subprocess.run(["bash", "-n", str(script)], check=True)

    def test_production_settings_pass_the_deploy_check(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("DJANGO_", "NMAS_"))}
        env.update(DJANGO_DEBUG="false", DJANGO_SECRET_KEY="x" * 64 + "-test-only-not-a-real-key-" + "y" * 20,
                   DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost", DJANGO_BEHIND_TRUSTED_PROXY="true",
                   DJANGO_SESSION_COOKIE_SECURE="true", DJANGO_SETTINGS_MODULE="config.settings")
        result = subprocess.run([sys.executable, "manage.py", "check", "--deploy", "--fail-level", "ERROR"],
                                cwd=Path(settings.BASE_DIR), env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # --- V2 Phase 5C: the probation soak collector scheduler -------------------------------------------------------------------
    def test_soak_tick_service_runs_the_collector_in_the_deployment_checkout(self):
        unit = self.read("systemd/nmas-probation-soak-tick.service")
        self.assertIn("Type=oneshot", unit)
        self.assertIn("WorkingDirectory=@DEPLOY_ROOT@/web", unit)                 # the deployment checkout, never a worktree path
        self.assertNotRegex(unit, r"clab_dualstack_lab-v2|/home/student/Scripts/clab")
        self.assertIn("EnvironmentFile=/etc/nmas/nmas-web.env", unit)             # secrets stay in the protected env file
        self.assertNotRegex(unit, r"Environment=.*(SECRET|TOKEN|PASSWORD)")
        exec_start = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
        self.assertEqual(exec_start, ["ExecStart=@VENV@/bin/python manage.py probation_soak_tick"])
        self.assertNotIn("--soak", unit)
        self.assertNotIn("sudo", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertNotIn("Restart=", unit)                                        # a failed tick is retried by the NEXT timer firing

    def test_soak_tick_timer_cadence_follows_the_sample_interval_and_never_backfills(self):
        from django.conf import settings
        timer = self.read("systemd/nmas-probation-soak-tick.timer")
        self.assertIn("Unit=nmas-probation-soak-tick.service", timer)
        self.assertIn("WantedBy=timers.target", timer)
        self.assertIn("Persistent=false", timer)                                  # downtime is a real gap; never back-filled
        import re
        minutes = int(re.search(r"^OnUnitActiveSec=(\d+)min$", timer, re.MULTILINE).group(1))
        interval = settings.PROBATION_SOAK_SAMPLE_INTERVAL_SECONDS
        self.assertLessEqual(minutes * 60, interval // 2)                         # at most half a sample interval (documented rule)
        self.assertGreaterEqual(minutes * 60, 60)                                 # and not needlessly aggressive
        self.assertNotIn("OnCalendar=*:*", timer)

    def test_soak_timer_install_script_is_explicit_and_refuses_an_unmigrated_checkout(self):
        script = self.read("scripts/install_soak_timer.sh")
        self.assertIn("set -euo pipefail", script)
        self.assertIn("--render-only", script)
        self.assertIn("manage.py migrate --check", script)
        self.assertIn("probation_soak_tick --dry-run", script)
        self.assertIn("systemd-analyze verify", script)
        self.assertNotRegex(script, r"NETBOX_TOKEN|SECRET_KEY=")
        self.assertLess(script.index("migrate --check"), script.index("systemctl enable --now"))

    def test_rendered_soak_units_pass_systemd_verification(self):
        import shutil
        import subprocess
        import tempfile
        if shutil.which("systemd-analyze") is None:
            self.skipTest("systemd-analyze is not available")
        script = DEPLOY / "scripts" / "install_soak_timer.sh"
        with tempfile.TemporaryDirectory() as out:
            done = subprocess.run(["bash", str(script), "--deploy-root", str(DEPLOY.parent), "--render-only", out, "--run-user", _CURRENT_USER,
                                   "--venv", sys.prefix], capture_output=True, text=True, timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr)
            rendered = (Path(out) / "nmas-probation-soak-tick.service").read_text()
            self.assertNotIn("@", "".join(line for line in rendered.splitlines() if not line.startswith("#")))
            verify = subprocess.run(["systemd-analyze", "verify", str(Path(out) / "nmas-probation-soak-tick.timer")], capture_output=True, text=True, timeout=30)
            self.assertEqual(verify.returncode, 0, verify.stderr)

    # --- V2 Phase 5B: the traffic runner ----------------------------------------------------------------------------------------
    def test_the_web_unit_keeps_its_hardening_and_gains_nothing_for_traffic(self):
        unit = self.read("systemd/nmas-web.service")
        for line in ("NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=full", "UMask=0027"):
            self.assertIn(line, unit.splitlines())
        for forbidden in ("nsenter", "sudo", "AmbientCapabilities", "CapabilityBoundingSet", "traffic", "docker.sock", "podman", "containerd"):
            self.assertNotIn(forbidden, unit)
        groups = [line for line in unit.splitlines() if line.startswith("SupplementaryGroups=")]
        self.assertEqual(groups, ["SupplementaryGroups=docker"])        # unchanged since V2 Phase 1 (device sessions); traffic added nothing

    def test_traffic_runner_socket_is_local_and_only_the_website_group_may_connect(self):
        unit = self.read("systemd/nmas-traffic-runner.socket")
        lines = [line for line in unit.splitlines() if line and not line.startswith("#")]
        self.assertEqual([line for line in lines if line.startswith("Listen")], ["ListenStream=/run/nmas-traffic-runner/runner.sock"])
        for line in ("SocketUser=root", "SocketGroup=@RUN_GROUP@", "SocketMode=0660", "Service=nmas-traffic-runner.service", "WantedBy=sockets.target"):
            self.assertIn(line, lines)
        self.assertNotRegex(unit, r"ListenStream=\[?[0-9:]|ListenDatagram|BindIPv6Only|SocketMode=06[67][2367]")   # no TCP, never world-accessible
        from django.conf import settings as django_settings
        self.assertEqual(django_settings.NMAS_TRAFFIC_RUNNER_SOCKET, "/run/nmas-traffic-runner/runner.sock")

    def test_traffic_runner_service_is_a_separate_sandboxed_account_running_root_owned_code(self):
        unit = self.read("systemd/nmas-traffic-runner.service")
        lines = [line for line in unit.splitlines() if line and not line.startswith("#")]
        for line in ("DynamicUser=yes", "SupplementaryGroups=docker", "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true",
                     "PrivateTmp=true", "PrivateDevices=true", "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any", "CapabilityBoundingSet=",
                     "AmbientCapabilities=", "MemoryDenyWriteExecute=true", "RestrictNamespaces=true", "SystemCallFilter=@system-service",
                     "WorkingDirectory=/usr/local/lib/nmas-traffic-runner", "Requires=nmas-traffic-runner.socket"):
            self.assertIn(line, lines)
        exec_start = [line for line in lines if line.startswith("ExecStart=")]
        self.assertEqual(exec_start, ["ExecStart=/usr/bin/python3 -E -s -B -m nmas_traffic_runner --config /etc/nmas/traffic-runner.json"])
        for forbidden in ("User=root", "User=@RUN_USER@", "EnvironmentFile", "@DEPLOY_ROOT@/web", "@VENV@", "--privileged", "sudo", "nsenter", "--socket"):
            self.assertNotIn(forbidden, "\n".join(lines))                 # not the website's account, code, venv or secrets

    def test_traffic_tools_image_is_pinned_minimal_and_not_a_nos_image(self):
        dockerfile = self.read("traffic-tools/Dockerfile")
        lines = [line.strip() for line in dockerfile.splitlines() if line.strip() and not line.startswith("#")]
        self.assertRegex(lines[0], r"^FROM alpine:[0-9.]+@sha256:[0-9a-f]{64}$")
        self.assertEqual(sum(line.startswith("FROM ") for line in lines), 1)
        packages = re.findall(r"^\s+([a-z0-9-]+)=([^ \\]+)", dockerfile, flags=re.M)
        self.assertEqual(sorted(name for name, _version in packages), ["iperf3", "iproute2-minimal", "iputils-ping", "python3", "traceroute"])
        for forbidden in ("ceos", "srlinux", "vrnetlab", "c8000v", "frr", "curl", "wget", "nmap", "netcat", "openssh", "bash", "sudo", "latest", "ADD "):
            self.assertNotIn(forbidden, dockerfile.lower() if forbidden != "ADD " else dockerfile)
        self.assertIn("USER 65534:65534", lines)
        self.assertIn('ENTRYPOINT ["/bin/false"]', lines)
        from core.services.traffic.runner import runtime
        baked = {fixed[2] for _entry, fixed, _raw in runtime.TOOLS.values() if fixed}
        self.assertEqual(baked, {f"/opt/nmas-traffic/{path.name}" for path in (DEPLOY / "traffic-tools" / "probes").glob("*.py")})
        for probe in (DEPLOY / "traffic-tools" / "probes").glob("*.py"):
            compile(probe.read_text(), str(probe), "exec")
            self.assertIn(f"probes/{probe.name}", dockerfile)

    def test_traffic_runner_install_script_installs_root_owned_code_and_never_touches_the_web_unit(self):
        script = self.read("scripts/install_traffic_runner.sh")
        for required in ("set -euo pipefail", "--render-only", "systemd-analyze verify", "install -m 0644 -o root -g root", "traffic_runner_config",
                         "--tools-image '$IMAGE_ID'", "--peer-uid '$RUN_UID'", "systemctl enable --now nmas-traffic-runner.socket",
                         "docker image inspect --format '{{.Id}}'"):
            self.assertIn(required, script)
        for forbidden in ("nmas-web.service", "usermod", "gpasswd", "sudoers", "chmod 666", "chmod 777", "0666", "NoNewPrivileges", "--privileged"):
            self.assertNotIn(forbidden, script.replace("It does not touch nmas-web.service", "").replace("keeps NoNewPrivileges", ""))
        self.assertNotRegex(script, r"NETBOX_TOKEN|SECRET_KEY=")
        self.assertLess(script.index("systemd-analyze verify"), script.index("systemctl enable --now"))

    def test_rendered_traffic_runner_units_pass_systemd_verification(self):
        import shutil
        import tempfile
        if shutil.which("systemd-analyze") is None:
            self.skipTest("systemd-analyze is not available")
        script = DEPLOY / "scripts" / "install_traffic_runner.sh"
        with tempfile.TemporaryDirectory() as out:
            done = subprocess.run(["bash", str(script), "--deploy-root", str(DEPLOY.parent), "--render-only", out, "--run-user", _CURRENT_USER],
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr)
            units = [str(Path(out) / name) for name in ("nmas-traffic-runner.socket", "nmas-traffic-runner.service")]
            for unit in units:
                rendered = Path(unit).read_text()
                self.assertNotIn("@", "".join(line for line in rendered.splitlines() if not line.startswith("#")).replace("@system-service", ""))
            verify = subprocess.run(["systemd-analyze", "verify", *units], capture_output=True, text=True, timeout=30)
            self.assertEqual(verify.returncode, 0, verify.stderr)
