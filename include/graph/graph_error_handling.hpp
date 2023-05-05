#ifndef GRAPH_ERROR_HANDLING_HPP
#define GRAPH_ERROR_HANDLING_HPP

#include <string_view>

namespace graph {
[[noreturn]] void terminate_with(std::string_view msg) noexcept;
} // namespace graph

#endif
