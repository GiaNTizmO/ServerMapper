cmake_minimum_required(VERSION 3.16)
project(ServerMapper)

set(CMAKE_CXX_STANDARD 17)

add_executable(ServerMapper main.cpp PortableExecutable.hpp CMapper.hpp CMapper.cpp)