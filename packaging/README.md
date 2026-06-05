# Packaging

This folder contains native package recipes for LxPerun.

## Fedora / dnf

Build an RPM with:

```bash
python -m build --sdist
cp dist/lxperun-0.1.0.tar.gz ~/rpmbuild/SOURCES/
rpmbuild -ba packaging/fedora/lxperun.spec
sudo dnf install ~/rpmbuild/RPMS/noarch/lxperun-0.1.0-1*.rpm
```

If you only have the RPM file, you can also install it directly with:

```bash
sudo dnf install ./lxperun-0.1.0-1*.rpm
```

## Arch / pacman

Build a local package with:

```bash
python -m build --sdist
cp dist/lxperun-0.1.0.tar.gz packaging/arch/
cd packaging/arch
makepkg -si
```

If you only have the built package file, you can also install it directly with:

```bash
sudo pacman -U ./lxperun-0.1.0-1-any.pkg.tar.zst
```

## Publishing

If you want `sudo dnf install lxperun` or `sudo pacman -S lxperun` to work
without local files, publish the built packages to a Fedora repository/COPR or
an Arch repository/AUR mirror.
