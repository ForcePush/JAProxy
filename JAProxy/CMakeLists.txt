cmake_minimum_required (VERSION 3.8)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

file(GLOB SRC_FILES
    *.cpp
    *.h
)


add_executable (JAProxy ${SRC_FILES})

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost COMPONENTS date_time thread system filesystem REQUIRED)
include_directories(
    ${Boost_INCLUDE_DIRS}
    "../third-party/cppbus/include"
    "../third-party/JKAProto/include"
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(PCAP REQUIRED)

target_link_libraries(
    JAProxy
    ${Boost_LIBRARIES}
    ${PCAP_LIBRARY}
    Threads::Threads
    JKAProto
)

if(MSVC)
  target_compile_options(JAProxy PRIVATE /W4 /WX)
else()
  target_compile_options(JAProxy PRIVATE -O3 -Wall -Wextra -pedantic -Wno-switch)
endif()

