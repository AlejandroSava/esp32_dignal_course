# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)
add_compile_definitions("KYBER_K=4")
add_compile_definitions("SHA_ACC=0")
add_compile_definitions("AES_ACC=0")
add_compile_definitions("INDCPA_KEYPAIR_DUAL=0")
add_compile_definitions("INDCPA_ENC_DUAL=0")
add_compile_definitions("INDCPA_DEC_DUAL=0")


set(EXTRA_COMPONENT_DIRS /home/alejandro/kybesp32_modification/components)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(22_kyber_example)
