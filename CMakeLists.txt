cmake_minimum_required(VERSION 3.16)
project(ite_flasher_cpp LANGUAGES CXX C)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)


# Enable Ninja generator explicitly if available
if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
message(STATUS "Switching to Ninja build system if available...")
endif()


# Add your source files here
set(SOURCES
src/main.cpp
src/util.c
src/ite_flasher.c
src/i2c_updater.cpp
src/spi_updater.cpp
)


add_executable(ite-flasher ${SOURCES})


target_include_directories(ite-flasher PRIVATE
${CMAKE_CURRENT_SOURCE_DIR}
${CMAKE_CURRENT_SOURCE_DIR}/include
)


# Link against libusb
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)


target_include_directories(ite-flasher PRIVATE ${LIBUSB_INCLUDE_DIRS})
target_link_libraries(ite-flasher PRIVATE ${LIBUSB_LIBRARIES})


target_compile_definitions(ite-flasher PRIVATE ${LIBUSB_CFLAGS_OTHER})


# Optional: enable more warnings
target_compile_options(ite-flasher PRIVATE -Wall -Wextra -Werror)


message(STATUS "To build with Ninja: run 'cmake -G Ninja -B build' then 'ninja -C build'")
