#!/bin/sh

copy_libraries () {
    cp -r /usr/local/tmplibsgx/* $SGX_LIBRARY_PATH
    rm -rf /usr/local/tmplibsgx
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

echo "Copy SGX Libs to /usr/local/libsgx/:"
copy_libraries
set_rpath
check_rpath
echo "Exit Shell"