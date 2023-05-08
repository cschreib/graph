cmake_minimum_required(VERSION 3.18)

project(graph-core LANGUAGES CXX VERSION 1.0.0)

include(FetchContent)

FetchContent_Declare(entt
                     GIT_REPOSITORY https://github.com/skypjack/entt.git
                     GIT_TAG        v3.11.1)
FetchContent_MakeAvailable(entt)

FetchContent_Declare(json
                     GIT_REPOSITORY https://github.com/nlohmann/json.git
                     GIT_TAG        v3.11.2)
FetchContent_MakeAvailable(json)

add_library(graph-core
    ${PROJECT_SOURCE_DIR}/include/graph/graph_core.hpp
    ${PROJECT_SOURCE_DIR}/include/graph/graph_error_handling.hpp
    ${PROJECT_SOURCE_DIR}/include/graph/graph_string.hpp
    ${PROJECT_SOURCE_DIR}/include/graph/graph_vector.hpp
    ${PROJECT_SOURCE_DIR}/src/graph_core.cpp
    ${PROJECT_SOURCE_DIR}/src/graph_error_handling.cpp)

add_library(graph::graph-core ALIAS graph-core)
set_target_properties(graph-core PROPERTIES EXPORT_NAME graph::graph-core)
target_compile_options(graph-core PUBLIC -DENTT_ID_TYPE=std::uint64_t)

target_compile_features(graph-core PUBLIC cxx_std_23)
target_include_directories(graph-core PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>)

target_link_libraries(graph-core PUBLIC EnTT::EnTT)
target_link_libraries(graph-core PUBLIC nlohmann_json::nlohmann_json)

if (GRAPH_DO_TEST)
    enable_testing()
    add_subdirectory(tests)
endif()
