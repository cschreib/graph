#include "graph/graph_string.hpp"

#include <entt/entity/registry.hpp>
#include <expected>
#include <nlohmann/json.hpp>
#include <string_view>

namespace graph {
graph::small_string<32>                       id_to_string(entt::entity e) noexcept;
std::expected<entt::entity, std::string_view> id_from_string(std::string_view s) noexcept;

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

std::expected<std::string_view, std::string_view>
get_node_type(const entt::registry& r, entt::entity node);

std::expected<std::string_view, std::string_view>
get_relationship_type(const entt::registry& r, entt::entity relationship);

std::expected<entt::entity, std::string_view>
get_relationship_target(const entt::registry& r, entt::entity relationship);

std::expected<entt::entity, std::string_view>
get_relationship_source(const entt::registry& r, entt::entity relationship);

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
