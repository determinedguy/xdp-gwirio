# gwirio

## Meaning

gwirio (/ˈɡwɪr.jɔ/, Welsh): to check, to verify

## Usage

To check XDP support.

## Prerequisites

You will need the BPF development libraries installed:

- Ubuntu/Debian: `sudo apt install libbpf-dev clang llvm libelf-dev`
- RHEL/CentOS: `sudo dnf install libbpf-devel clang llvm elfutils-libelf-devel`

## Compile and Run

To compile, simply run `make`.

To run, run `sudo ./xdp_test <your_interface_name>`.

> Check the used interface name from `ifconfig`.
