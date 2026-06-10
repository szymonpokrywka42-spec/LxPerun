from pathlib import Path
import tempfile
import unittest

from lxperun.network import SocketEntry, arp_table, conntrack_entries, group_sockets, network_bandwidth, socket_diag


class NetworkTest(unittest.TestCase):
    def test_socket_diag_maps_socket_inodes_to_pids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_net = root / "proc" / "net"
            proc_net.mkdir(parents=True)
            (proc_net / "tcp").write_text(
                "\n".join(
                    [
                        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode",
                        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345",
                    ]
                ),
                encoding="utf-8",
            )
            (proc_net / "udp").write_text("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n", encoding="utf-8")
            (proc_net / "unix").write_text("Num RefCount Protocol Flags Type St Inode Path\n", encoding="utf-8")
            proc = root / "proc"
            fd_dir = proc / "1234" / "fd"
            fd_dir.mkdir(parents=True)
            (fd_dir / "0").symlink_to("socket:[12345]")

            entries = socket_diag(proc_net=proc_net, proc_root=proc)

            tcp = next(entry for entry in entries if entry.protocol == "tcp")
            self.assertEqual(tcp.local_address, "127.0.0.1")
            self.assertEqual(tcp.local_port, 8080)
            self.assertEqual(tcp.state, "LISTEN")
            self.assertEqual(tcp.pids, (1234,))

    def test_arp_conntrack_and_bandwidth_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_net = root / "proc" / "net"
            proc_net.mkdir(parents=True)
            (proc_net / "arp").write_text(
                "\n".join(
                    [
                        "IP address       HW type     Flags       HW address            Mask     Device",
                        "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0",
                    ]
                ),
                encoding="utf-8",
            )
            (proc_net / "nf_conntrack").write_text(
                "ipv4     2 tcp 6 431999 ESTABLISHED src=192.168.1.10 dst=1.1.1.1 sport=12345 dport=443 packets=3 bytes=200\n",
                encoding="utf-8",
            )
            (proc_net / "dev").write_text(
                "\n".join(
                    [
                        "Inter-|   Receive                                                |  Transmit",
                        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
                        " eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0",
                    ]
                ),
                encoding="utf-8",
            )

            arp = arp_table(proc_net)
            conntrack = conntrack_entries(proc_net)
            bw = network_bandwidth(proc_net / "dev", timestamp=10.0)
            prev = network_bandwidth(proc_net / "dev", timestamp=5.0)
            bw_delta = network_bandwidth(proc_net / "dev", previous=prev, timestamp=10.0)

            self.assertEqual(arp[0].device, "wlan0")
            self.assertEqual(conntrack[0].src, "192.168.1.10")
            self.assertEqual(bw.interfaces[0].rx_bytes, 1000)
            self.assertEqual(bw_delta.interfaces[0].rx_rate_bps, 0.0)

    def test_group_sockets_splits_listening_established_and_unix(self) -> None:
        sockets = (
            SocketEntry(protocol="tcp", state="LISTEN", local_address="0.0.0.0", local_port=80, remote_address="", remote_port=0, inode=1, pids=(1,)),
            SocketEntry(protocol="tcp", state="ESTABLISHED", local_address="127.0.0.1", local_port=1234, remote_address="127.0.0.1", remote_port=4321, inode=2, pids=(2,)),
            SocketEntry(protocol="unix", state="CONNECTED", local_address="/run/foo", local_port=0, remote_address="", remote_port=0, inode=3, pids=(), path="/run/foo"),
        )

        grouped = group_sockets(sockets)

        self.assertEqual(len(grouped["listening"]), 1)
        self.assertEqual(len(grouped["established"]), 1)
        self.assertEqual(len(grouped["unix"]), 1)


if __name__ == "__main__":
    unittest.main()
