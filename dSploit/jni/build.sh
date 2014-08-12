#!/bin/bash

oldpwd=$(pwd)

UPDATE_SERVER="http://update.dsploit.net/"

die() {
	echo "FAILED"
	echo "--------------------------------------------------"
	echo "an error occurred while creating the $pkg package."
	echo "see build.log for more info"
	echo "--------------------------------------------------"
	
	cd "${oldpwd}"
	exit 1
}

create_archive_metadata() {
  echo -n "creating metadata file..."
  md5=$(md5sum "$1" 2>&3 | grep -oE "[0-9a-f]{32}")
  test -n "${md5}" || die
  sha1=$(sha1sum "$1" 2>&3 | grep -oE "[0-9a-f]{40}")
  test -n "${sha1}" || die
  filename=$(basename "$1")
  cat > "$2" 2>&3 <<EOF
{
  "url" : "${UPDATE_SERVER}${filename}",
  "name" : "${filename}",
  "version" : $3,
  "archiver" : "$4",
  "compression" : "$5",
  "md5" : "${md5}",
  "sha1" : "${sha1}"
}
EOF
  echo -ne "ok\n"
}

test -d "${oldpwd}" || die

exec 3> build.log

pkg="tools"
nmap_data="nmap-mac-prefixes
nmap-payloads
nmap-rpc
nmap-os-db
nmap-protocols
nmap-services
nmap-service-probes"
ndk_empty_scripts="build-host-executable.mk
build-host-shared-library.mk
build-host-static-library.mk"

echo "*** creating tools package ***"

ndk_build=$(which ndk-build) || \
(echo "android NDK not found, please ensure that it's directory is in your PATH"; die)

ndk_dir=$(dirname "${ndk_build}")
ndk_dir="${ndk_dir}/build/core/"

sudo=""

test -w "${ndk_dir}" || sudo="sudo"

for s in $ndk_empty_scripts; do
  if [ ! -f "${ndk_dir}${s}" ]; then
    $sudo touch "${ndk_dir}${s}" >&3 2>&1 || die
  fi
done

echo -n "building native executables..."
ndk-build -j$(grep -E "^processor" /proc/cpuinfo | wc -l) >&3 2>&1 || die
echo -ne "ok\ncopying programs..."
for tool in nmap fusemounts; do
	mkdir -p ./tools/$tool >&3 2>&1
	cp ../libs/armeabi/$tool ./tools/$tool/$tool >&3 2>&1 || die
done
echo -ne "ok\ncopying scripts..."
find ./nmap -name "*.lua" -print0 | rsync -aq --files-from=- --from0 ./ ./tools/ >&3 2>&1 || die
rsync -aq ./nmap/scripts/ ./tools/nmap/scripts/ >&3 2>&1 || die

echo -ne "ok\ncopying configuration/database files..."
for f in $nmap_data; do
	cp ./nmap/$f ./tools/nmap/ >&3 2>&1 || die
done

echo -ne "ok\ncreating archive..."
zip -qr tools.zip tools >&3 2>&1 || die
echo "ok"
rm -rf tools >&3 2>&1 || die
if [ ! -d ../assets ]; then
	mkdir ../assets >&3 2>&1 || die
fi
mv tools.zip ../assets/ >&3 2>&1 || die
