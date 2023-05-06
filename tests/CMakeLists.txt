include(FetchContent)

FetchContent_Declare(snitch
                     GIT_REPOSITORY https://github.com/cschreib/snitch.git
                     GIT_TAG        v1.1.1)
FetchContent_MakeAvailable(snitch)

add_executable(graph_runtime_tests graph.cpp)
target_link_libraries(graph_runtime_tests PRIVATE snitch::snitch)
target_link_libraries(graph_runtime_tests PRIVATE graph::graph)
