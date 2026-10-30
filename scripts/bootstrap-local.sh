#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
root=$PWD
mkdir -p .tools/packages .tools/root
cd .tools/packages
# Ubuntu 24.04 amd64 package versions used for the recorded experiments.
apt-get download iperf=2.1.9+dfsg-1 iperf3=3.16-1build2 \
    libiperf0=3.16-1build2 libsctp1=1.0.19+dfsg-2build1
for package in ./*.deb; do
    dpkg-deb -x "$package" "$root/.tools/root"
done
sha256sum ./*.deb > "$root/references/deb-sha256.txt"
