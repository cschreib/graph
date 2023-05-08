cmake_minimum_required(VERSION 3.18)

project(graph-core LANGUAGES CXX VERSION 0.1.0)

# Maximum lengths.
set(GRAPH_CORE_MAX_PROPERTIES                     16  CACHE STRING "Max number of property per node or relationship")
set(GRAPH_CORE_MAX_SCHEMA_NODES                   32  CACHE STRING "Max number of unique node types")
set(GRAPH_CORE_MAX_SCHEMA_RELATIONSHIPS           32  CACHE STRING "Max number of unique relationship types")
set(GRAPH_CORE_MAX_STRING_ID_LENGTH               32  CACHE STRING "Max length of a node or relationship type name")
set(GRAPH_CORE_MAX_INPLACE_STRING_PROPERTY_LENGTH 128 CACHE STRING "Max length of string property for inplace storage")

if (GIT_COMMAND_SUCCESS EQUAL 0)
    set(GRAPH_CORE_FULL_VERSION "${PROJECT_VERSION}.${GIT_COMMIT_HASH}")
else()
    set(GRAPH_CORE_FULL_VERSION "${PROJECT_VERSION}")
endif()

# Create configure file to store CMake build parameter
configure_file("${PROJECT_SOURCE_DIR}/include/graph/graph_core_config.hpp.config"
               "${PROJECT_BINARY_DIR}/graph/graph_core_config.hpp")

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
