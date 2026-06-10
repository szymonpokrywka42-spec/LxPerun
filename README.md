# LxPerun

LxPerun is a command-line diagnostics toolkit for developers, admins, and
anyone who wants deeper visibility into Linux than a classic fetch-style tool
can provide. The goal is a fast inventory tool, debugger, and bug finder for
software and hardware — without bypassing security boundaries or behaving like
malware.

LxPerun reads data from `/proc`, `/sys`, `/etc/os-release`, syscalls, and
optionally system tools such as `systemctl`, `journalctl`, `dmesg`, `perf`,
`bpftool`, `fwupdmgr`, or TPM tools when they are available.

## Example

```python
from lxperun.linux import snapshot

info = snapshot()
print(info.identity.hostname)
print(info.memory.used_percent)
```

CLI:

```bash
lxperun snapshot
lxperun doctor --raw
lxperun all --limit 5

# without installation:
python -m lxperun.cli snapshot
python -m lxperun.cli snapshot --json
python -m lxperun.cli doctor
python -m lxperun.cli doctor --json
python -m lxperun.cli rings
python -m lxperun.cli capabilities
python -m lxperun.cli network
python -m lxperun.cli security
python -m lxperun.cli firewall
python -m lxperun.cli performance
python -m lxperun.cli containers
python -m lxperun.cli processes
python -m lxperun.cli services
python -m lxperun.cli storage
python -m lxperun.cli hardware
python -m lxperun.cli trace
python -m lxperun.cli crash
python -m lxperun.cli clean
python -m lxperun.cli report
python -m lxperun.cli all
python -m lxperun.cli help
```

After installation, the `lxperun` and `lxperun-sys` commands are available.

If you installed LxPerun with `pipx`, `sudo lxperun` may not be found because
`sudo` often uses a restricted `PATH`. You can either run:

```bash
sudo env "PATH=$PATH" lxperun all
```

If you prefer a native package manager install, you can still use the packaged
RPM so the command is available system-wide.

By default, LxPerun shows friendly, readable values. If you want raw numbers,
add `--raw`; if you want to disable colors, use `--no-color`; if you want to
automatically rerun a command with sudo and unlock deeper checks, add `--root`.

`snapshot` collects raw facts: kernel, distro, CPU, RAM, disks, mounts, network,
kernel modules, and selected sysctl values.

`doctor` interprets those facts: high RAM/disk/swap usage, tainted kernel,
interfaces without IPs, failed systemd units, kernel log errors from
`journalctl`/`dmesg`, and Python syntax errors in the current project.

`rings` shows the access map from ring 3 to firmware/platform-security layers:
what is visible with the current permissions, what is missing, and what safe
next steps exist. LxPerun performs legal introspection only; it does not try to
bypass kernel, hypervisor, UEFI, Intel ME, or AMD PSP isolation.

`capabilities` shows what LxPerun can realistically diagnose with the current
permissions: procfs, sysfs, `/dev/kmsg`, perf, eBPF, audit, systemd, journal,
EFI, TPM, fwupd, and debug symbols.

`network` reads `/proc/net/*` and shows listening sockets, per-PID ownership,
ARP neighbors, conntrack entries, and interface bandwidth snapshots. Use
`--watch` for a live refresh loop.

`security` checks posture signals such as SELinux/AppArmor status, sockets
bound to all interfaces, UID 0 accounts, passwordless shadow entries when run
as root, container/cgroup markers, runtime API sockets, namespace visibility,
and world-writable paths under `/etc`, `/opt`, and `/usr/local`. Add `--root`
to unlock deeper checks.

`firewall` audits iptables/nftables rules and maps listening sockets to allow
or block decisions where possible.

`performance` shows PSI pressure, interrupt/softirq load distribution, and the
heaviest slab caches. Add `--raw` if you want the underlying counters instead of
human-friendly labels.

`containers` is a focused view of the container signals already discovered by
the security scan: cgroups, runtime sockets, and namespace visibility.

`processes` reads `/proc/<pid>` and shows processes, RSS memory, fd count,
state, user, command line, and zombies.

`services` reads `systemctl` and shows service health: total, active, running,
failed, and a list of failed units.

`storage` shows mounts, block devices, and I/O stats from the kernel.

`hardware` shows PCI, USB, hwmon, and NUMA.

`trace` shows readiness for syscall debugging and profiling, or runs a command
under `strace` or `perf`.

`crash` shows readiness for coredump analysis, a list of recent coredumps, and
optionally details about the newest coredump.

`clean` reclaims disk space safely: it dry-runs by default, then can remove old
coredumps, run `flatpak uninstall --unused`, and clean supported package caches
when you pass `--apply`.

`report` generates one coherent artifact in `markdown` or `json` and can write
it to a file. This is the best option for bug reports and sharing results.

Example:

```bash
python -m lxperun.cli report --format markdown --output lxperun-report.md --latest
python -m lxperun.cli report --format json --output lxperun-report.json
```

`all` runs the current full report set: snapshot, capabilities, security,
containers, firewall, performance, rings, doctor, network, processes, services,
storage, hardware, trace, and crash. Use `--json` if you want full data for
scripts.

Most commands work without root and will still show useful partial data. When a
command can benefit from deeper privileges, LxPerun prints a tip telling you to
rerun it with `--root`.

## GitHub publishing

The easiest way to distribute LxPerun online is through **GitHub Releases**.
The workflow in `.github/workflows/release.yml` builds distribution files for
`v*` tags and uploads them as release assets.

After publishing, users can:

```bash
curl -LO https://github.com/<your-user>/<your-repo>/releases/download/v0.1.1/lxperun-0.1.1-py3-none-any.whl
pip install ./lxperun-0.1.1-py3-none-any.whl
```

Or download the source tarball from the release and install locally:

```bash
tar -xf lxperun-0.1.1.tar.gz
cd lxperun-0.1.1
python -m pip install .
```

If you want to return later to native `dnf`/`pacman` packaging, the recipes are
still available in `packaging/`.

Tests:

```bash
python -m unittest discover -s tests
```

## License

LxPerun is licensed under the GNU General Public License v3.0 or later. See
`LICENSE`.
