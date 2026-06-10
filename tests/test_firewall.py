from types import SimpleNamespace
import unittest

from lxperun.firewall import firewall_report


class FirewallTest(unittest.TestCase):
    def test_firewall_report_maps_listening_socket_to_accept_rule(self) -> None:
        listener = SimpleNamespace(protocol="tcp", local_address="0.0.0.0", local_port=22, pids=(1,))

        def fake_which(command: str) -> str | None:
            return f"/usr/sbin/{command}"

        def fake_run(command: list[str], timeout: float) -> tuple[int, str, str]:
            if command[0].endswith("iptables"):
                return (
                    0,
                    "\n".join(
                        [
                            "Chain INPUT (policy DROP)",
                            "num  target     prot opt source               destination",
                            "1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22",
                        ]
                    ),
                    "",
                )
            if command[0].endswith("nft"):
                return (
                    0,
                    "\n".join(
                        [
                            "table inet filter {",
                            " chain input {",
                            "  type filter hook input priority 0; policy drop;",
                            "  tcp dport 22 accept",
                            " }",
                            "}",
                        ]
                    ),
                    "",
                )
            raise AssertionError(command)

        report = firewall_report(
            network_report_obj=SimpleNamespace(listening_sockets=(listener,)),
            which_fn=fake_which,
            run_command_fn=fake_run,
        )

        self.assertTrue(report.backends[0].available)
        self.assertTrue(any(mapping.decision == "allowed" for mapping in report.mappings))


if __name__ == "__main__":
    unittest.main()
