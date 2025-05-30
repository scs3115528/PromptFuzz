#!/bin/bash

source ../common.sh

PROJECT_NAME=libzip
STALIB_NAME=libzip.a
DYNLIB_NAME=libzip.so
DIR=$(pwd)


function download() {
    apt-get update && apt-get install -y cmake pkg-config zlib1g-dev libbz2-dev liblzma-dev libzstd-dev
    cd $SRC
    git clone --depth 1 https://github.com/nih-at/libzip.git
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build/lib
    rm -rf $WORK/build
    mkdir -p $WORK/build
    cd $WORK/build
    cmake -DBUILD_SHARED_LIBS=ON -DENABLE_GNUTLS=OFF -DENABLE_MBEDTLS=OFF -DENABLE_OPENSSL=ON -DBUILD_TOOLS=OFF -DHAVE_CRYPTO=ON $SRC/libzip
    make -j$(nproc)
    cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_GNUTLS=OFF -DENABLE_MBEDTLS=OFF -DENABLE_OPENSSL=ON -DBUILD_TOOLS=OFF -DHAVE_CRYPTO=ON $SRC/libzip
    make -j$(nproc)
}

function build_oss_fuzz() {
    for fuzzer in $(make list-fuzzers | sed -n 's/^FUZZERS: //p')
    do
        $CXX $CFLAGS -I. -I$SRC/libzip/lib \
	$SRC/libzip/ossfuzz/$fuzzer.c \
	-o $OUT/$fuzzer \
	$LIB_FUZZING_ENGINE $WORK/build/lib/libzip.a -lbz2 -llzma -lz -lzstd -v -lssl -lcrypto
    done
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cd ${SRC}/
    cp ./libzip/lib/zip_source_file_win32.h ./libzip/lib/zip_crypto.h ./libzip/lib/zip_source_file_stdio.h ./libzip/lib/zip_crypto_mbedtls.h ./libzip/lib/zip_crypto_openssl.h ./libzip/lib/compat.h ./libzip/lib/zip_crypto_commoncrypto.h ./libzip/lib/zip.h ./libzip/lib/zip_source_file.h ./libzip/lib/zip_crypto_gnutls.h ./libzip/lib/zipint.h ./libzip/lib/zip_crypto_win.h ./libzip/src/getopt.h ./libzip/src/diff_output.h ./libzip/ossfuzz/zip_read_fuzzer_common.h $WORK/build/config.h $WORK/build/zipconf.h  ${LIB_BUILD}/include/
#   cp ./libzip/lib/zip.h ${LIB_BUILD}/include/
}

function build_corpus() {
    cd $SRC/libzip/regress
    find . -name "*zip" | \
	         xargs zip $OUT/zip_read_fuzzer_seed_corpus.zip

    cp $SRC/libzip/ossfuzz/zip_write_encrypt_aes256_file_fuzzer_seed_corpus.zip $OUT/

    mkdir ${LIB_BUILD}/corpus
    unzip $OUT/zip_read_fuzzer_seed_corpus.zip -d ${LIB_BUILD}/corpus
    cp $SRC/libzip/ossfuzz/zip_write_encrypt_aes256_file_fuzzer_seed_corpus.zip ${LIB_BUILD}/corpus
    
}

function build_dict() {
    cp $SRC/libzip/ossfuzz/zip_read_fuzzer.dict ${LIB_BUILD}/fuzzer.dict
}

build_all
