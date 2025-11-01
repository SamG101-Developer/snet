cmake_minimum_required(VERSION 4.1.2)
set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "d0edc3af-4c50-42ea-a356-e2862fe7a444")
project(snet LANGUAGES CXX)

# C++ Standard + Modules settings.
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_MODULE_STD ON)

# Custom OpenSSL paths.
set(OPENSSL_ROOT_DIR "/usr/local")
set(OPENSSL_INCLUDE_DIR "/usr/local/include")
set(OPENSSL_LIBRARIES "/usr/local/lib")

# Dependencies.
find_package(PkgConfig REQUIRED)
find_package(OpenSSL 3.6.0 REQUIRED)
find_package(spdlog REQUIRED)
find_package(nlohmann_json 3.11.3 REQUIRED)
find_package(CLI11 1.9.1 REQUIRED)
find_package(ipaddress REQUIRED)
find_package(SerEx REQUIRED)
pkg_check_modules(DEPS REQUIRED glib-2.0 libsecret-1)

# Collect source files.
file(GLOB_RECURSE MODULE_SOURCES CONFIGURE_DEPENDS src/*.cpp)
add_library(${PROJECT_NAME}_lib STATIC ${MODULE_SOURCES})

# Executables (main and test).
add_executable(${PROJECT_NAME} main.cpp)

target_include_directories(
        ${PROJECT_NAME}_lib PRIVATE include ${DEPS_INCLUDE_DIRS})

target_sources(
        ${PROJECT_NAME}_lib PUBLIC FILE_SET CXX_MODULES FILES ${MODULE_SOURCES})

target_compile_options(
        ${PROJECT_NAME}_lib PRIVATE -fmodules-ts)

target_link_libraries(
        ${PROJECT_NAME}_lib PRIVATE OpenSSL::SSL OpenSSL::Crypto spdlog::spdlog SerEx::SerEx
        nlohmann_json::nlohmann_json CLI11::CLI11 ipaddress::ipaddress ipaddress::ipaddress-module ${DEPS_LIBRARIES})

# Link the executables to the library.
target_link_libraries(
        ${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_lib)


# Add the test folder as a subdirectory.
add_subdirectory(test)