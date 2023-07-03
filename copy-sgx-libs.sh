#!/bin/sh
libs=$(ldd $SGX_TMP_LIBRARY_PATH/libp11sgx.so | grep sgx | awk '{print $3}')

for lib in $libs; do
  cp $lib $SGX_TMP_LIBRARY_PATH/
done