#!/bin/bash
set -e

echo "Installing OpenSSL development headers..."
sudo apt-get update && sudo apt-get install -y libssl-dev build-essential autoconf libtool

echo "Downloading and building GF-Complete..."
git clone https://github.com/ceph/gf-complete.git
cd gf-complete
./autogen.sh
./configure
make
sudo make install
cd ..

echo "Downloading and building Jerasure..."
git clone https://github.com/ceph/jerasure.git
cd jerasure
autoreconf --force --install
./configure
make
sudo make install
cd ..

echo "Updating shared library cache..."
sudo ldconfig

echo "Setup complete! You can now run 'make'."