cmake_minimum_required(VERSION 3.5)

project(enum_example LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5Core)
find_package(Boost REQUIRED system)

add_executable(enum_example main.cpp)
target_link_libraries(enum_example Qt5::Core pthread)
