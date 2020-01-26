#!/bin/bash
declare -r ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd -P)"
declare -r VARIANTS_DIR="${ROOT_DIR}/variants"

declare -r VERSION="3.10.4"
declare -r COMMIT=844da56d0864cf3a522f58b475e10fd6e7e6ee5b

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
