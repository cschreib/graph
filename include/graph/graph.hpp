#include <entt/entity/registry.hpp>
#include <nlohmann/json.hpp>
#include <string_view>

namespace graph {
constexpr std::size_t max_key_length = 32;

void load_schema(entt::registry& r, const nlohmann::json& schema);
bool add_node(entt::registry& r, const nlohmann::json& node);
}
