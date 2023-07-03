#!/bin/sh

copy_libraries () {
    # mkdir $SGX_LIBRARY_PATH
    cp -r $SGX_TMP_LIBRARY_PATH/* $SGX_LIBRARY_PATH
    # rm -rf $SGX_TMP_LIBRARY_PATH
}

set_rpath () {
    ls $SGX_LIBRARY_PATH
    libs=$(ls $SGX_LIBRARY_PATH | grep -v 'libp11SgxEnclave.signed.so')
    for lib in $libs; do
        patchelf --set-rpath $SGX_LIBRARY_PATH $SGX_LIBRARY_PATH/$lib
    done
}

check_rpath () {
    libs=$(ls $SGX_LIBRARY_PATH | grep -v 'libp11SgxEnclave.signed.so')
    for lib in $libs; do
        patchelf --print-rpath $SGX_LIBRARY_PATH/$lib
    done
}

copy_libraries
set_rpath
check_rpath
./sds/sds-server wait
