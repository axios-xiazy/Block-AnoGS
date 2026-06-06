cmake_minimum_required(VERSION 3.14)
project(BlockAnoGS CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

find_package(GTest REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(block_anogs_tests
    tests/test_library_info.cpp
    tests/test_file_ops.cpp
    tests/test_memory.cpp
    tests/test_signals.cpp
    tests/test_seccomp.cpp
)

target_compile_options(block_anogs_tests PRIVATE -Wall -Wextra)
target_link_libraries(block_anogs_tests GTest::gtest GTest::gtest_main pthread)

include(GoogleTest)
gtest_discover_tests(block_anogs_tests)
