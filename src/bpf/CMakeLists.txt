cmake_minimum_required(VERSION 3.10)

# Название компонента
set(target flb4_bpf)

project(${target} LANGUAGES C)

# Исходные файлы
file(GLOB_RECURSE SOURCE_FILE
    *.c
)

# Опции компилятора для clang
set(CLANG_FLAGS "-O2 -target bpf")

# Проверка наличия clang
find_program(CLANG clang)

if(NOT CLANG)
    message(FATAL_ERROR "Clang не найден!")
endif()

# Целевая компиляция
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/flb4.bpf.o
    COMMAND ${CLANG} -O2 -target bpf -I${LIBBPF_INC_DIR} -I${CMAKE_CURRENT_SOURCE_DIR} -g -c "${SOURCE_FILE}" -o ${CMAKE_BINARY_DIR}/flb4.bpf.o
    COMMAND bpftool gen skeleton ${CMAKE_BINARY_DIR}/flb4.bpf.o > ${CMAKE_SOURCE_DIR}/src/Flb4.h
    DEPENDS ${SOURCE_FILE}
)

add_custom_target(${target} ALL DEPENDS ${CMAKE_BINARY_DIR}/flb4.bpf.o)
