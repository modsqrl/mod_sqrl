#!/bin/bash
#
# Download compile and install the library
# dependencies for mod_sqrl.
#
# Copy this script to /usr/local/src and run it.
# If you are not root but are a member of the wheel group,
# change the group for /usr/local/src to wheel and make
# it group writable:
#   sudo chgrp wheel /usr/local/src
#   sudo chmod g+w /usr/local/src
#

apr_dn="apr-1.5.0"
apr_fn="${apr_dn}.tar.gz"
apr_url="http://apache.osuosl.org/apr/${apr_fn}"

apu_dn="apr-util-1.5.3"
apu_fn="${apu_dn}.tar.gz"
apu_url="http://apache.osuosl.org/apr/${apu_fn}"

httpd_dn="httpd-2.2.26"
httpd_fn="${httpd_dn}.tar.gz"
httpd_url="http://apache.claz.org/httpd/${httpd_fn}"

apreq_dn="libapreq2-2.13"
apreq_fn="${apreq_dn}.tar.gz"
apreq_url="http://www.apache.org/dist/httpd/libapreq/${apreq_fn}"

sodium_dn="libsodium-0.4.5"
sodium_fn="${sodium_dn}.tar.gz"
sodium_url="https://github.com/jedisct1/libsodium/releases/download/0.4.5/libsodium-0.4.5.tar.gz"


cd $(dirname "$0")


# Download apr if it hasn't already been downloaded
if [ ! -e "${apr_fn}" ]
then
  echo "Downloading apr from '${apr_url}'"
  curl -o "${apr_fn}" "$apr_url"
fi

# Extract apr
if [ ! -e "${apr_dn}" ]
then
  echo "Extracting the apr source"
  tar -xzf "${apr_fn}"
fi

echo "Entering ${apr_dn}"
cd "${apr_dn}"

# Compile apr
if [ ! -e ".libs/libapr-1.so" ]
then
  echo "Configuring apr"
  ./configure --prefix=/usr/local --enable-nonportable-atomics --enable-threads
  echo "Compiling apr"
  make
  echo "Installing apr with sudo"
  sudo make install
fi

echo "Exiting ${apr_dn}"
cd ../

# Download apu if it hasn't already been downloaded
if [ ! -e "${apu_fn}" ]
then
  echo "Downloading apu from '${apu_url}'"
  curl -o "${apu_fn}" "$apu_url"
fi

# Extract apu
if [ ! -e "${apu_dn}" ]
then
  echo "Extracting the apu source"
  tar -xzf "${apu_fn}"
fi

echo "Entering ${apu_dn}"
cd "${apu_dn}"

# Compile apu
if [ ! -e ".libs/libaprutil-1.so" ]
then
  echo "Configuring apu"
  ./configure --prefix=/usr/local --with-apr=/usr/local/bin/apr-1-config --with-crypto --with-openssl=yes --with-dbm=sdbm --with-mysql=yes --with-sqlite3=yes
  echo "Compiling apu"
  make
  echo "Installing apu with sudo"
  sudo make install
fi

echo "Exiting ${apu_dn}"
cd ../

# Download httpd if it hasn't already been downloaded
if [ ! -e "${httpd_fn}" ]
then
  echo "Downloading httpd from '${httpd_url}'"
  curl -o "${httpd_fn}" "$httpd_url"
fi

# Extract httpd
if [ ! -e "${httpd_dn}" ]
then
  echo "Extracting the httpd source"
  tar -xzf "${httpd_fn}"
fi

echo "Entering ${httpd_dn}"
cd "${httpd_dn}"

# Compile httpd
if [ ! -e "httpd" ]
then
  echo "Configuring httpd"
  ./configure --prefix=/usr/local/apache22 --with-apr=/usr/local/bin/apr-1-config --with-apr-util=/usr/local/bin/apu-1-config --enable-mods-shared="most ssl" --with-mpm=worker
  echo "Compiling httpd"
  make
  echo "Installing httpd with sudo"
  sudo make install
fi

echo "Exiting ${httpd_dn}"
cd ../

# Download apreq if it hasn't already been downloaded
if [ ! -e "${apreq_fn}" ]
then
  echo "Downloading apreq2 from '${apreq_url}'"
  curl -o "${apreq_fn}" "$apreq_url"
fi

# Extract apreq
if [ ! -e "${apreq_dn}" ]
then
  echo "Extracting the apreq2 source"
  tar -xzf "${apreq_fn}"
fi

echo "Entering ${apreq_dn}"
cd "${apreq_dn}"

# Compile apreq
if [ ! -e ".libs/libapreq2.so" ]
then
  echo "Configuring apreq2"
  ./configure --prefix=/usr/local --with-apache2-apxs=/usr/local/apache22/bin/apxs --with-apr-config=/usr/local/bin/apr-1-config --with-apu-config=/usr/local/bin/apu-1-config
  echo "Compiling apreq2"
  make
  echo "Installing apreq2 with sudo"
  sudo make install
fi

echo "Exiting ${apreq_dn}"
cd ../

# Download sodium if it hasn't already been downloaded
if [ ! -e "${sodium_fn}" ]
then
  echo "Downloading libsodium from '${sodium_url}'"
  URL=`curl "$sodium_url" | grep -oEi 'href="([^"]+)"' | cut -d'"' -f2`
  echo "$URL"
  echo "${URL//&amp;/&}"
  curl -o "${sodium_fn}" "${URL//&amp;/&}"
fi

# Extract sodium
if [ ! -e "${sodium_dn}" ]
then
  echo "Extracting the libsodium source"
  tar -xzf "${sodium_fn}"
fi

echo "Entering ${sodium_dn}"
cd "${sodium_dn}"

# Compile sodium
if [ ! -e ".libs/libsodium.so" ]
then
  echo "Configuring libsodium"
  ./configure --prefix=/usr/local
  echo "Compiling libsodium"
  make
  echo "Installing libsodium with sudo"
  sudo make install
fi

echo "Exiting ${sodium_dn}"
cd ../

