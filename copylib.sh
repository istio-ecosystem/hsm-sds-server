#!/bin/sh

copy_libraries () {
    # mkdir $SGX_LIBRARY_PATH
    cp -r $SGX_TMP_LIBRARY_PATH/* $SGX_LIBRARY_PATH
    rm -rf $SGX_TMP_LIBRARY_PATH
    echo "Copy Finished"
}

set_rpath () {
    ls $SGX_LIBRARY_PATH
    patchelf --set-rpath $SGX_LIBRARY_PATH $SGX_LIBRARY_PATH/libp11sgx.so
    patchelf --set-rpath $SGX_LIBRARY_PATH $SGX_LIBRARY_PATH/libsgx_dcap_ql.so.1
    patchelf --set-rpath $SGX_LIBRARY_PATH $SGX_LIBRARY_PATH/libsgx_enclave_common.so.1
    patchelf --set-rpath $SGX_LIBRARY_PATH $SGX_LIBRARY_PATH/libsgx_pce_logic.so.1
    patchelf --set-rpath $SGX_LIBRARY_PATH $SGX_LIBRARY_PATH/libsgx_qe3_logic.so
    patchelf --set-rpath $SGX_LIBRARY_PATH $SGX_LIBRARY_PATH/libsgx_urts.so
    echo "Set rpath finished"
}

check_rpath () {
    patchelf --print-rpath $SGX_LIBRARY_PATH/libp11sgx.so
    patchelf --print-rpath $SGX_LIBRARY_PATH/libsgx_dcap_ql.so.1
    patchelf --print-rpath $SGX_LIBRARY_PATH/libsgx_enclave_common.so.1
    patchelf --print-rpath $SGX_LIBRARY_PATH/libsgx_pce_logic.so.1
    patchelf --print-rpath $SGX_LIBRARY_PATH/libsgx_qe3_logic.so
    patchelf --print-rpath $SGX_LIBRARY_PATH/libsgx_urts.so
}

echo "Copy SGX Libs to $SGX_LIBRARY_PATH:"
copy_libraries
set_rpath
check_rpath
echo "Exit Shell"