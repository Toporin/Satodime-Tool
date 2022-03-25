#!/bin/bash

NAME_ROOT=SatodimeTool 

# These settings probably don't need any change
export WINEPREFIX=/opt/wine64
export WINEDEBUG=-all
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=22

PYHOME=c:/python3
PYTHON="wine $PYHOME/python.exe -OO -B"


# Let's begin!
set -e

here="$(dirname "$(readlink -e "$0")")"

. "$CONTRIB"/build_tools_util.sh

pushd $WINEPREFIX/drive_c/electrum

VERSION=`git describe --tags --dirty --always`
info "Last commit: $VERSION"


find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd

info "installing pip."
$PYTHON -m ensurepip
$PYTHON -m pip install --upgrade pip

# Install frozen dependencies
#info "Pip installing dependencies"
#$PYTHON -m pip install --no-warn-script-location -r "$CONTRIB"/deterministic-build/requirements.txt
# $PYTHON -m pip install --no-warn-script-location -r "$CONTRIB"/deterministic-build/requirements-hw.txt

pushd $WINEPREFIX/drive_c/electrum
# see https://github.com/pypa/pip/issues/2195 -- pip makes a copy of the entire directory
info "Pip installing SatodimeTool. This might take a long time if the project folder is large."
$PYTHON -m pip install --no-warn-script-location .
#$PYTHON -m pip install --no-warn-script-location /pypackage # to install pysatochip package from local folder
#$PYTHON -m pip install --no-warn-script-location /pypackage2 # to install pybitcointools package from local folder
popd

rm -rf dist/

# build standalone and portable versions
info "Running pyinstaller..."
# ls
# ls ../..
#wine "$PYHOME/scripts/pyinstaller.exe" --noconfirm --ascii --clean --name $NAME_ROOT-$VERSION -w deterministic.spec
info "Running pyinstaller 2..."
wine "$PYHOME/scripts/pyinstaller.exe" -cF --clean --name SatodimeTool-console-v.exe --additional-hooks-dir=. --add-data "../../SatodimeTool/*.png;." --add-data "../../SatodimeTool/help/*.txt;help/" --add-data "../../SatodimeTool/api_keys.ini;."  "../../SatodimeTool/satodime_tool.py" -i "../../SatodimeTool/satochip.ico" 
wine "$PYHOME/scripts/pyinstaller.exe" -wF --clean --name SatodimeTool-v.exe --additional-hooks-dir=. --add-data "../../SatodimeTool/*.png;." --add-data "../../SatodimeTool/help/*.txt;help/" --add-data "../../SatodimeTool/api_keys.ini;."  "../../SatodimeTool/satodime_tool.py" -i "../../SatodimeTool/satochip.ico" 

# set timestamps in dist, in order to make the installer reproducible
pushd dist
find -exec touch -d '2000-11-11T11:11:11+00:00' {} +
popd


info "Padding binaries to 8-byte boundaries, and fixing COFF image checksum in PE header"
# note: 8-byte boundary padding is what osslsigncode uses:
#       https://github.com/mtrojnar/osslsigncode/blob/6c8ec4427a0f27c145973450def818e35d4436f6/osslsigncode.c#L3047
(
    cd dist
    for binary_file in ./*.exe; do
        info ">> fixing $binary_file..."
        # code based on https://github.com/erocarrera/pefile/blob/bbf28920a71248ed5c656c81e119779c131d9bd4/pefile.py#L5877
        python3 <<EOF
pe_file = "$binary_file"
with open(pe_file, "rb") as f:
    binary = bytearray(f.read())
pe_offset = int.from_bytes(binary[0x3c:0x3c+4], byteorder="little")
checksum_offset = pe_offset + 88
checksum = 0

# Pad data to 8-byte boundary.
remainder = len(binary) % 8
binary += bytes(8 - remainder)

for i in range(len(binary) // 4):
    if i == checksum_offset // 4:  # Skip the checksum field
        continue
    dword = int.from_bytes(binary[i*4:i*4+4], byteorder="little")
    checksum = (checksum & 0xffffffff) + dword + (checksum >> 32)
    if checksum > 2 ** 32:
        checksum = (checksum & 0xffffffff) + (checksum >> 32)

checksum = (checksum & 0xffff) + (checksum >> 16)
checksum = (checksum) + (checksum >> 16)
checksum = checksum & 0xffff
checksum += len(binary)

# Set the checksum
binary[checksum_offset : checksum_offset + 4] = int.to_bytes(checksum, byteorder="little", length=4)

with open(pe_file, "wb") as f:
    f.write(binary)
EOF
    done
)

sha256sum dist/SatodimeTool*.exe
