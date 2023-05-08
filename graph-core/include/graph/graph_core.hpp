#ifndef GRAPH_CORE_HPP
#define GRAPH_CORE_HPP

#include "graph/graph_string.hpp"

#include <entt/entity/registry.hpp>
#include <expected>
#include <nlohmann/json.hpp>
#include <string_view>

namespace graph {
using json     = nlohmann::json;
using registry = entt::registry;
using entity   = entt::entity;
template<typename T>
using expected = std::expected<T, std::string_view>;

small_string<32> id_to_string(entity e) noexcept;
expected<entity> id_from_string(std::string_view s) noexcept;

expected<void> load_schema(registry& r, const json& schema);
json           dump_schema(const registry& r);

expected<void> load_nodes(registry& r, const json& nodes);
json           dump_nodes(const registry& r);

expected<void> load_relationships(registry& r, const json& relationships);
json           dump_relationships(const registry& r);

expected<void> load(registry& r, const json& data);
json           dump(const registry& r);

expected<entity> add_node(registry& r, const json& node);

expected<void> add_node(registry& r, entity e, const json& node);

expected<void> replace_node(registry& r, entity e, const json& node);

expected<entity> add_relationship(registry& r, const json& relationship);

expected<void> add_relationship(registry& r, entity e, const json& relationship);

expected<void> replace_relationship(registry& r, entity e, const json& relationship);

expected<std::string_view> get_node_type(const registry& r, entity node);

expected<std::string_view> get_relationship_type(const registry& r, entity relationship);

expected<entity> get_relationship_target(const registry& r, entity relationship);

expected<entity> get_relationship_source(const registry& r, entity relationship);

expected<json> get_node_property(const registry& r, entity node, std::string_view property);

expected<json>
get_relationship_property(const registry& r, entity relationship, std::string_view property);

expected<json> get_node_properties(const registry& r, entity node);

expected<json> get_relationship_properties(const registry& r, entity node);

expected<json> get_node(const registry& r, entity node);

expected<json> get_relationship(const registry& r, entity relationship);

expected<json> get_node_relationships(const registry& r, entity node);

expected<json> get_node_relationships(const registry& r, entity node, std::string_view type);

expected<json> get_nodes(const registry& r, std::string_view type);

expected<json> get_relationships(const registry& r, std::string_view type);

expected<void> delete_node(registry& r, entity node);

expected<void> delete_relationship(registry& r, entity relationship);
} // namespace graph

#endif
