cmake_minimum_required(VERSION 3.20)
project(gen_waf_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
find_program(CLANG_EXECUTABLE clang REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(genwaf_common
  src/common/effective_config.cpp
  src/common/waf_runtime.cpp
)

target_include_directories(genwaf_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(gendp
  src/gendp/main.cpp
)
target_link_libraries(gendp PRIVATE genwaf_common)
target_link_libraries(gendp PRIVATE Threads::Threads)
target_link_libraries(gendp PRIVATE OpenSSL::Crypto)

set(GENWAF_XDP_BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/genwaf_xdp.bpf.o)

add_custom_command(
  OUTPUT ${GENWAF_XDP_BPF_OBJECT}
  COMMAND ${CLANG_EXECUTABLE}
          -O2
          -g
          -target bpf
          -D__TARGET_ARCH_x86
          -I/usr/include
          -I/usr/include/x86_64-linux-gnu
          -c ${CMAKE_CURRENT_SOURCE_DIR}/src/genxdp_loader/genwaf_xdp.bpf.c
          -o ${GENWAF_XDP_BPF_OBJECT}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/genxdp_loader/genwaf_xdp.bpf.c
  COMMENT "Building GEN WAF XDP eBPF object"
)

add_custom_target(genwaf_xdp_bpf ALL DEPENDS ${GENWAF_XDP_BPF_OBJECT})

add_executable(genxdp-loader
  src/genxdp_loader/main.cpp
)
target_include_directories(genxdp-loader PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_compile_definitions(genxdp-loader PRIVATE GENWAF_BPF_OBJECT_DEFAULT="${GENWAF_XDP_BPF_OBJECT}")
add_dependencies(genxdp-loader genwaf_xdp_bpf)
target_link_libraries(genxdp-loader PRIVATE genwaf_common ${LIBBPF_LIBRARIES})
