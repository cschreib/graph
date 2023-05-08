cmake_minimum_required(VERSION 3.18)

project(graph-rest LANGUAGES CXX VERSION 1.0.0)

include(FetchContent)

FetchContent_Declare(crow
                     GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
                     GIT_TAG        v1.0+5)
FetchContent_MakeAvailable(crow)

add_library(graph-rest
    ${PROJECT_SOURCE_DIR}/include/graph/graph_rest.hpp
    ${PROJECT_SOURCE_DIR}/src/graph_rest.cpp)

add_library(graph::graph-rest ALIAS graph-rest)
set_target_properties(graph-rest PROPERTIES EXPORT_NAME graph::graph-rest)

target_compile_features(graph-rest PUBLIC cxx_std_23)
target_include_directories(graph-rest PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>)

target_link_libraries(graph-rest PUBLIC graph-core)
target_link_libraries(graph-rest PUBLIC Crow::Crow)

if (GRAPH_DO_TEST)
    enable_testing()
    add_subdirectory(tests)
endif()
