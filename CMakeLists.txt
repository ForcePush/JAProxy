cmake_minimum_required (VERSION 3.8)

project ("JAProxy")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")

add_subdirectory ("JAProxy")
add_subdirectory ("third-party/JKAProto")