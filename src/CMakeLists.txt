cmake_minimum_required(VERSION 3.21)

# Название компонента
set(target flb4)

project(${target})

# Исходные файлы. Находятся в той-же директории
file(GLOB_RECURSE sources
    *.h
    *.c
    *.cpp
)

# Создаём исполняемы таргет
add_executable(${target} ${sources})

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

target_link_libraries(${target} PUBLIC ${CMAKE_SOURCE_DIR}/submodules/libbpf/src/root/usr/lib64/libbpf.a elf z /usr/local/lib/libzstd.a yaml-cpp::yaml-cpp)

# Необходимо, чтобы таргет flb4_bpf отработал раньше, т.к. он генерирует header-файл в user программу
add_dependencies(${target} flb4_bpf)

# Складываем всё в директорию run
set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/run)

