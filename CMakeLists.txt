cmake_minimum_required(VERSION 3.21)

set(target root)


# Для работы автокомплита и анализатора
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_COMPILER "/usr/bin/clang")

set(LIBBPF_INC_DIR ${CMAKE_SOURCE_DIR}/lib/libbpf/src/root/usr/include)
set(RUN_DIR ${CMAKE_SOURCE_DIR}/run)

project(${target})

add_subdirectory(src/core)
add_subdirectory(src/usr)