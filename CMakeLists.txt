#井表示注释
CMAKE_MINIMUM_REQUIRED( VERSION 2.8 )
PROJECT( binTrans )

set( CMAKE_EXPORT_COMPILE_COMMANDS ON)

SET( CMAKE_CXX_COMPILER "g++")

set( CMAKE_BUILD_TYPE Debug )

# 设置编译选项
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -O0 -g -ggdb -lelf" )

if(NOT TARGET spdlog)
    # Stand-alone build
    find_package(spdlog REQUIRED)
endif()

if(NOT TARGET fmt)
    # Stand-alone build
    find_package(fmt REQUIRED)
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)

# aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SOURCE)

set(binTrans_SOURCE
        src/binTrans.cpp
        src/bpf_jit.cpp
        src/riscv-disas.c
        src/map_manager.cpp
    )

add_executable(binTrans ${binTrans_SOURCE})

target_link_libraries(binTrans spdlog::spdlog fmt::fmt elf)

# set(map_manager_SOURCE
#         src/map_manager.cpp
#     )

# add_executable(map_manager ${map_manager_SOURCE})
# TARGET_LINK_LIBRARIES(map_manager elf)


