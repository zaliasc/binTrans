#井好表示注释
CMAKE_MINIMUM_REQUIRED( VERSION 2.8 )
PROJECT( binTrans )

SET(CMAKE_CXX_COMPILER "g++")

set( CMAKE_BUILD_TYPE Debug )

# 设置编译选项
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -g" )

if(NOT TARGET spdlog)
    # Stand-alone build
    find_package(spdlog REQUIRED)
endif()

if(NOT TARGET fmt)
    # Stand-alone build
    find_package(fmt REQUIRED)
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SOURCE)

add_executable(binTrans ${DIR_SOURCE})

target_link_libraries(binTrans spdlog::spdlog fmt::fmt)


