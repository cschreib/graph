#include "graph/graph_string.hpp"

#include <entt/entity/registry.hpp>
#include <expected>
#include <nlohmann/json.hpp>
#include <string_view>

namespace graph {
constexpr std::size_t max_key_length = 32;

void           load_schema(entt::registry& r, const nlohmann::json& schema);
nlohmann::json save_schema(const entt::registry& r);

std::expected<entt::entity, std::string_view>
add_node(entt::registry& r, const nlohmann::json& node);
} // namespace graph
