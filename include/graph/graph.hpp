#include "graph/graph_string.hpp"

#include <entt/entity/registry.hpp>
#include <expected>
#include <nlohmann/json.hpp>
#include <string_view>

namespace graph {
std::expected<void, std::string_view> load_schema(entt::registry& r, const nlohmann::json& schema);
nlohmann::json                        dump_schema(const entt::registry& r);

std::expected<void, std::string_view> load_nodes(entt::registry& r, const nlohmann::json& nodes);
nlohmann::json                        dump_nodes(const entt::registry& r);

std::expected<void, std::string_view>
               load_relationships(entt::registry& r, const nlohmann::json& relationships);
nlohmann::json dump_relationships(const entt::registry& r);

std::expected<void, std::string_view> load(entt::registry& r, const nlohmann::json& data);
nlohmann::json                        dump(const entt::registry& r);

std::expected<entt::entity, std::string_view>
add_node(entt::registry& r, const nlohmann::json& node);

std::expected<entt::entity, std::string_view>
add_node(entt::registry& r, entt::entity e, const nlohmann::json& node);

std::expected<entt::entity, std::string_view>
add_relationship(entt::registry& r, const nlohmann::json& relationship);

std::expected<entt::entity, std::string_view>
add_relationship(entt::registry& r, entt::entity e, const nlohmann::json& relationship);

std::expected<nlohmann::json, std::string_view>
get_node_property(const entt::registry& r, entt::entity node, std::string_view property);

std::expected<nlohmann::json, std::string_view> get_relationship_property(
    const entt::registry& r, entt::entity relationship, std::string_view property);

std::expected<nlohmann::json, std::string_view>
get_node_properties(const entt::registry& r, entt::entity node);

std::expected<nlohmann::json, std::string_view>
get_relationship_properties(const entt::registry& r, entt::entity node);

std::expected<nlohmann::json, std::string_view>
get_node_relationships(const entt::registry& r, entt::entity node);

std::expected<nlohmann::json, std::string_view>
get_node_relationships(const entt::registry& r, entt::entity node, std::string_view type);
} // namespace graph
