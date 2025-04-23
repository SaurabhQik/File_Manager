cmake_minimum_required(VERSION 3.10)
project(file_manager_service)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Add source files
add_executable(file_manager_service 
    src/main.cpp
)

# Find required packages
find_package(Threads REQUIRED)
target_link_libraries(file_manager_service PRIVATE Threads::Threads)

find_package(OpenSSL REQUIRED)
target_link_libraries(file_manager_service PRIVATE OpenSSL::Crypto)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(file_manager_service PRIVATE wsock32 ws2_32)
endif()

# Create necessary directories in the build directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/storage)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/storage/chunks)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/storage/metadata)

# Ensure permissions and correct output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Set the output directory to make sure it exists
file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# Optionally, clean up the old build files
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Cleaning up old build files..."
)

# Add the clean-all target as a dependency of the build process
add_dependencies(file_manager_service clean-all)
