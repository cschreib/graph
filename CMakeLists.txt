cmake_minimum_required(VERSION 3.18)

project(graph LANGUAGES CXX VERSION 1.0.0)

# Figure out git hash, if any
execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    RESULT_VARIABLE GIT_COMMAND_SUCCESS
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)

add_subdirectory(graph-core)
add_subdirectory(graph-rest)
