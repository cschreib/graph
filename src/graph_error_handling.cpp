#include "graph/graph_error_handling.hpp"

#include <cstdio> // for std::fwrite
#include <exception> // for std::terminate

namespace {
void stdout_print(std::string_view message) noexcept {
    std::fwrite(message.data(), sizeof(char), message.length(), stdout);
}
} // namespace

namespace graph {
[[noreturn]] void terminate_with(std::string_view msg) noexcept {
    stdout_print("terminate called with message: ");
    stdout_print(msg);
    stdout_print("\n");

    std::terminate();
}
} // namespace graph
