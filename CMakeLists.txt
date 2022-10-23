cmake_minimum_required(VERSION 3.22)
project(hash_password_algorism C)

set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "OpenSSL Found!")
endif()

include_directories(/usr/include/mysql)
include_directories(/usr/include/seccomp)

add_executable(hash_password_algorithm main.c)

target_link_libraries(hash_password_algorithm OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(hash_password_algorithm mysqlclient)
target_link_libraries(hash_password_algorithm seccomp)