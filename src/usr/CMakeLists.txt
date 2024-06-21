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

# Линкуем bpf
target_link_libraries(${target} bpf)
target_include_directories(${target} PRIVATE -L${CMAKE_SOURCE_DIR}/lib/libbpf/root/usr/include)

# Необходимо, чтобы таргет flb4_bpf отработал раньше, т.к. он генерирует header-файл в user программу
add_dependencies(${target} flb4_bpf)

# Складываем всё в директорию run
set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/run)

