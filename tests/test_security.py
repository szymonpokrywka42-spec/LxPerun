from pathlib import Path
from types import SimpleNamespace
import os
import socket
import tempfile
import unittest

from lxperun.security import security_report


class SecurityTest(unittest.TestCase):
    def test_selinux_and_apparmor_signals_are_detected_from_sysfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sys" / "fs" / "selinux").mkdir(parents=True)
            (root / "sys" / "fs" / "selinux" / "enforce").write_text("1", encoding="utf-8")
            (root / "sys" / "module" / "apparmor" / "parameters").mkdir(parents=True)
            (root / "sys" / "module" / "apparmor" / "parameters" / "enabled").write_text("Y", encoding="utf-8")

            report = security_report(
                root=root,
                network_report_obj=SimpleNamespace(listening_sockets=()),
                is_root_fn=lambda: 1000,
            )

            selinux = next(signal for signal in report.signals if signal.name == "selinux")
            apparmor = next(signal for signal in report.signals if signal.name == "apparmor")
            self.assertTrue(selinux.available)
            self.assertIn("enforcing", selinux.detail)
            self.assertTrue(apparmor.available)
            self.assertIn("enabled", apparmor.detail)

    def test_exposed_listeners_create_network_finding(self) -> None:
        listener = SimpleNamespace(protocol="tcp", local_address="0.0.0.0", local_port=8080, pids=(1234,))

        report = security_report(
            root=Path("/"),
            network_report_obj=SimpleNamespace(listening_sockets=(listener,)),
            is_root_fn=lambda: 1000,
        )

        self.assertTrue(any(finding.category == "network" for finding in report.findings))
        self.assertTrue(any("8080" in evidence for finding in report.findings for evidence in finding.evidence))

    def test_uid0_and_shadow_checks_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            etc = root / "etc"
            etc.mkdir()
            (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\nadmin:x:0:0:admin:/root:/bin/bash\n", encoding="utf-8")
            (etc / "shadow").write_text("root::19358:0:99999:7:::\nadmin::19358:0:99999:7:::\n", encoding="utf-8")

            report = security_report(
                root=root,
                network_report_obj=SimpleNamespace(listening_sockets=()),
                is_root_fn=lambda: 0,
            )

            categories = {finding.category for finding in report.findings}
            self.assertIn("accounts", categories)
            self.assertTrue(any("Multiple UID 0" in finding.message for finding in report.findings))
            self.assertTrue(any("Passwordless" in finding.message for finding in report.findings))

    def test_world_writable_paths_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            etc = root / "etc"
            etc.mkdir()
            world_writable = etc / "perun-test.conf"
            world_writable.write_text("demo", encoding="utf-8")
            os.chmod(world_writable, 0o666)

            report = security_report(
                root=root,
                network_report_obj=SimpleNamespace(listening_sockets=()),
                is_root_fn=lambda: 1000,
            )

            permission_findings = [finding for finding in report.findings if finding.category == "permissions"]
            self.assertTrue(permission_findings)
            self.assertIn(str(world_writable), permission_findings[0].evidence)

    def test_symlinks_do_not_trigger_world_writable_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            etc = root / "etc"
            etc.mkdir()
            target = root / "shared.conf"
            target.write_text("demo", encoding="utf-8")
            os.chmod(target, 0o666)
            (etc / "shared.conf").symlink_to(target)

            report = security_report(
                root=root,
                network_report_obj=SimpleNamespace(listening_sockets=()),
                is_root_fn=lambda: 1000,
            )

            permission_findings = [finding for finding in report.findings if finding.category == "permissions"]
            self.assertFalse(permission_findings)

    def test_container_signals_and_runtime_socket_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            (proc / "1").mkdir(parents=True)
            (proc / "1" / "cgroup").write_text("0::/docker/1234\n", encoding="utf-8")
            for namespace_name in ("pid", "net", "mnt"):
                namespace_dir = proc / "1" / "ns"
                namespace_dir.mkdir(exist_ok=True)
                (namespace_dir / namespace_name).symlink_to(f"{namespace_name}:[4026531836]")
            self_ns_dir = proc / "self" / "ns"
            self_ns_dir.mkdir(parents=True)
            for namespace_name in ("pid", "net", "mnt"):
                (self_ns_dir / namespace_name).symlink_to(f"{namespace_name}:[4026532448]")

            run_dir = root / "run"
            run_dir.mkdir()
            docker_socket = run_dir / "docker.sock"
            podman_dir = run_dir / "podman"
            podman_dir.mkdir()
            podman_socket = podman_dir / "podman.sock"
            for socket_path in (docker_socket, podman_socket):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    sock.bind(str(socket_path))
                finally:
                    sock.close()

            report = security_report(
                root=root,
                network_report_obj=SimpleNamespace(listening_sockets=()),
                is_root_fn=lambda: 1000,
            )

            container_signal = next(signal for signal in report.signals if signal.name == "container")
            namespace_signal = next(signal for signal in report.signals if signal.name == "namespaces")
            self.assertTrue(container_signal.available)
            self.assertTrue(namespace_signal.available)
            self.assertTrue(any(finding.category == "container" for finding in report.findings))


if __name__ == "__main__":
    unittest.main()
