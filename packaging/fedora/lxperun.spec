Name:           lxperun
Version:        0.1.0
Release:        1%{?dist}
Summary:        Friendly Linux diagnostics toolkit for developers and admins
License:        GPL-3.0-or-later
URL:            https://example.invalid/lxperun
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros

%description
LxPerun is a small Linux diagnostics toolkit that inspects system state,
processes, storage, hardware, trace readiness, and crash data.

%prep
%autosetup -n %{name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files lxperun

%files -n %{name} -f %{pyproject_files}
%license LICENSE
%doc README.md

