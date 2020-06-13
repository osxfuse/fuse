#!/bin/bash
declare -r ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd -P)"
declare -r VARIANTS_DIR="${ROOT_DIR}/variants"

declare -r VERSION="3.10.5"
declare -r COMMIT=8d54048c015166c5a53f1026d91344443d1d9f30

function main
{
    local variant="${1:-osxfuse}"

    git clone https://github.com/osxfuse/fuse.git libfuse
    pushd libfuse > /dev/null
    git checkout ${COMMIT}

    ./makeconf.sh && \
    CFLAGS="-DOSXFUSE_VERSION=\\\"${VERSION}\\\" -include ${VARIANTS_DIR}/${variant}.h" \
    ./configure --disable-dependency-tracking --disable-static --disable-example && \
    make -j 4

    popd > /dev/null
}

main "${@}"
