cmake_minimum_required(VERSION 3.15)
project(ELFsign)

#set(CMAKE_CXX_STANDARD 14)
# Set include dir and src dir
set (PROJECT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
message (STATUS "source -> ${PROJECT_SOURCE_DIR}/src")
message (STATUS "include -> ${PROJECT_INCLUDE_DIR}")
include_directories(${PROJECT_INCLUDE_DIR})

# Set 3rd library
link_libraries (ssl crypto)

# Set marco value
set (KEY_LENGTH 2048)
set (PUB_KEY_FILE "\"./pubkey.pem\"")
set (PRI_KEY_FILE "\"./prikey.pem\"")
set (CERTIFICATE_FILE "\"./ELFSign.pem\"")
set (LOG_MODE 0)

configure_file (
        "${PROJECT_INCLUDE_DIR}/config.h.in"
        "${PROJECT_INCLUDE_DIR}/config.h"
)


add_subdirectory (${PROJECT_SOURCE_DIR}/src)
aux_source_directory (${PROJECT_SOURCE_DIR}/src DIR_SRCS)

add_executable (ELFSign ${DIR_SRCS})
message ("src codes -> " ${DIR_SRCS})

target_link_libraries (ELFSign source)
