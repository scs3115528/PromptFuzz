# PromptFuzz总结
## 一、简介
项目地址：https://github.com/PromptFuzz/PromptFuzz  
论文介绍：https://dl.acm.org/doi/pdf/10.1145/3658644.3670396  
主创博客：https://yunlongs.cn/  
## 二、用法
以项目cJSON为例  
1.环境搭建
```
https://github.com/PromptFuzz/PromptFuzz
cd PromptFuzz
docker build -t promptfuzz .
docker run -it promptfuzz bash
```
2.llm参数设置
```
export OPENAI_API_KEY=$(your_key)
export OPENAI_MODEL_NAME=$(your_model_name)
export OPENAI_PROXY_BASE='https://api.uniapi.me/v1'
```
3.项目运行
```
# 项目运行构建，结果在output/build中
cd data/cJSON
./build.sh

# prompt llm生成fuzz
cargo run --bin fuzzer -- cJSON -c $(nproc) -r --fuzzer-run --fr 10

按理说这里生成10个成功的fuzz之后，我可以在对应的文件夹下将它们找到，但是succ_seeds下面只有一个fuzzers
我把所有的driver都放在一个文件夹下了
之后融合所有fuzz
cargo run --bin harness -- cJSON fuse-fuzzer corrent_program/

运行融合之后的driver，运行24小时
cargo run --bin harness -- cJSON fuzzer-run 86400 true

获取覆盖
cargo run --bin harness -- libaom coverage collect
cargo run --bin harness -- libaom coverage report

得到report
llvm-cov report ./fuzzer_cov --instr-profile=default.profdata
llvm-cov show ./fuzzer_cov --instr-profile=default.profdata --format=html -output-dir=./coverage_report
```
## 三、传入一个新项目
参考文档
https://github.com/FuzzAnything/PromptFuzz/blob/main/data/README.md
### 尝试项目一：libzip
#### 1.编写config.yaml
内容包括项目名，静态库名称，动态库名称，不参加的函数等等
```
project_name: libzip
static_lib_name: libzip.a
dyn_lib_name: libzip.so
ban:
  - zip_register_progress_callback_with_state
  - zip_register_progress_callback_with_state
null_term: true
landmark: true
```
可以添加的选项有
The following three fields are mandatory for all library:  
project_name: Type(String)  
static_lib_name: Type(String)  
dyn_lib_name: Type(String)  
Those three fields should be same to the PROJECT_NAME, STALIB_NAME and DYNLIB_NAME you write in build.sh.  
We have also provided some options for you to fine-tune on each project. In most cases, using the default values for these options is sufficient. However, for libraries designed with specific mechanisms, you may need to adjust them to appropriate values in order to increase effectiveness or minimize false positives.  
ban: Type(Option<Vec<String>>, default=None). The list of functions you do not want to use.  
null_term: Type(bool, default=false). If true, the random input passed from fuzzer will be appended with a terminal character of '\x00'.  
extra_c_flags: Type(Option<Vec<String>>, default=None), The list of compiler flags you want to add in the compilations of programs.  
landmark: Type(bool, default=None). If true, choose an corpora from fuzzing copus and provide it as an input example to LLMs.  
force_types: Type(Option<Vec<String>>, default=None). The list of custom types you want to be always prompted to LLMs.  
fuzz_fork: Type(Option<bool>, default=false). If true, run LibFuzzer in the fork mode.  
desc: Type(Option<String>, default=None). Provided short description of this library to let LLMs know what the library is.  
spec: Type(Option<String>, default=None). The library specifications used in the library.  
init_file: Type(Option<String>, default=None). The initialization file used in library setup.  
asan_options: Type(Option, defalut=None). The extra ASAN options used for sanitization.  
disable_fmemopen: Type(bool, default=false). If true, disable the usage of fmemopen and replace it to fopen.  
rss_limit_mb: Type(Option, default=None). The memory limit that allowed for each fuzz driver in this library.   
#### 2.编写build.sh
- download: specify where to download this project.
- build_lib: specify the commands to build this library. The commands could be directly copyied from OSS-Fuzz.
- build_oss_fuzz: specify how to build the interal fuzzers of this project. Could be directly copyied from OSS-Fuzz.
- build_corpus: download the fuzzer corpus and copy them to ${LIB_BUILD}/corpus.
- build_dict: download the fuzzer dictionary and copy them to ${LIB_BUILD}/fuzzer.dict.
- copy_include: copy the header files that you want to analyze to ${LIB_BUILD}/include.
```
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
```
#### 3.执行fuzzer
```
cargo run --bin fuzzer -- libzip
```
发现出现一直没有下一步结果  
逐步打印，发现他是在寻找type时出错  
发现传入的include的h文件不全，重新增加新的  
```
clang++ -fsyntax-only -H -I. zip.h
```
重新执行还是不行，重新打印log，发现他是在这两个函数是出错，注释这两个函数
```
  - zip_register_progress_callback_with_state
  - zip_register_progress_callback_with_state
```
可能是因为这两个函数有空指针  
重新运行，发现没有出现正常的fuzz  

