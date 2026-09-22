cmake_minimum_required(VERSION 3.20)
project(example)

include(ExternalProject)
ExternalProject_Add(
  thirdparty_lib
  URL https://downloads.example.invalid/thirdparty-1.2.3.tar.gz
  PREFIX ${CMAKE_BINARY_DIR}/thirdparty
)
