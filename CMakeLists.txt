cmake_minimum_required(VERSION 3.16)

project(pidesfire-contract VERSION 0.1.0 LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(test_contract
    tests/test_contract.cpp
)

target_include_directories(test_contract PRIVATE ${CMAKE_SOURCE_DIR})

add_test(NAME contract_tests COMMAND test_contract)
