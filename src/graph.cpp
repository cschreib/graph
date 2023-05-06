#include "graph/graph.hpp"

#include "graph/graph_string.hpp"
#include "graph/graph_vector.hpp"

#include <algorithm>

using namespace entt::literals;
using namespace std::literals;

namespace {
constexpr std::size_t max_properties       = 16;
constexpr std::size_t max_schema_nodes     = 32;
constexpr std::size_t max_schema_links     = 32;
constexpr std::size_t max_string_id_length = 32;

struct hashed_string {
    entt::id_type                             hash{};
    graph::small_string<max_string_id_length> str{};
};

struct node_type {
    entt::id_type type{};
};

struct link_type {
    entt::id_type type{};
};

struct schema_property {
    hashed_string name{};
    hashed_string type{};
};

struct schema_node {
    hashed_string                                        type{};
    graph::small_vector<schema_property, max_properties> properties{};
};

struct schema_link {
    hashed_string                                        type{};
    hashed_string                                        source{};
    hashed_string                                        target{};
    graph::small_vector<schema_property, max_properties> properties{};
};

struct schema {
    graph::small_vector<schema_node, max_schema_nodes> nodes{};
    graph::small_vector<schema_link, max_schema_links> links{};
};

entt::id_type hash(std::string_view s) noexcept {
    return entt::hashed_string::value(s.data(), s.size());
}

hashed_string add_hash(std::string_view s) noexcept {
    return hashed_string{.hash = hash(s), .str = s};
}

template<typename Item>
schema_property& load_schema_property(Item& r, std::string_view name, const nlohmann::json& data) {
    return r.properties.push_back(
        {.name = add_hash(name), .type = add_hash(data.get<std::string>())});
}

template<typename Storage>
auto& load_schema_item(Storage& r, std::string_view name, const nlohmann::json& data) {
    typename Storage::value_type item{.type = add_hash(name)};
    if (data.contains("properties"sv)) {
        for (const auto& [k, v] : data["properties"sv].items()) {
            if (std::string_view(k).starts_with("__")) {
                continue;
            }

            load_schema_property(item, k, v);
        }
    }

    return r.push_back(item);
}

template<typename Storage>
auto& load_schema_link(Storage& r, std::string_view name, const nlohmann::json& data) {
    if (!data.contains("source"sv)) {
        throw std::runtime_error("missing 'source' element");
    }
    if (!data.contains("target"sv)) {
        throw std::runtime_error("missing 'target' element");
    }

    auto& l = load_schema_item(r, name, data);

    l.source = add_hash(data["source"sv].get<std::string>());
    l.target = add_hash(data["target"sv].get<std::string>());

    return l;
}

struct type_less {
    static entt::id_type get_type(const auto& n) noexcept {
        return n.type.hash;
    }

    static entt::id_type get_type(entt::id_type s) noexcept {
        return s;
    }

    bool operator()(const auto& n1, const auto& n2) const noexcept {
        return get_type(n1) < get_type(n2);
    }
};

const schema_node* get_node_schema(const entt::registry& r, entt::id_type type) noexcept {
    const auto& s    = r.ctx().get<schema>();
    auto        iter = std::lower_bound(s.nodes.begin(), s.nodes.end(), type, type_less{});
    if (iter == s.nodes.end() || iter->type.hash != type) {
        return nullptr;
    }

    return &*iter;
}

const schema_link* get_link_schema(const entt::registry& r, entt::id_type type) noexcept {
    const auto& s    = r.ctx().get<schema>();
    auto        iter = std::lower_bound(s.links.begin(), s.links.end(), type, type_less{});
    if (iter == s.links.end() || iter->type.hash != type) {
        return nullptr;
    }

    return &*iter;
}

template<typename Item>
const schema_property* get_property_schema(const Item& n, entt::id_type name) noexcept {
    auto iter =
        std::find_if(n.properties.begin(), n.properties.end(), [&](const schema_property& p) {
            return p.name.hash == name;
        });

    if (iter == n.properties.end()) {
        return nullptr;
    }

    return &*iter;
}

std::expected<void, std::string_view>
check_property_schema(const schema_property& s, const nlohmann::json& p) noexcept {
    switch (s.type.hash) {
    case "string"_hs: {
        if (!p.is_string()) {
            return std::unexpected("expected string value"sv);
        }
        break;
    }
    case "integer"_hs: {
        if (!p.is_number_integer()) {
            return std::unexpected("expected integer value"sv);
        }
        break;
    }
    case "float"_hs: {
        if (!p.is_number_float()) {
            return std::unexpected("expected float value"sv);
        }
        break;
    }
    case "bool"_hs: {
        if (!p.is_boolean()) {
            return std::unexpected("expected boolean value"sv);
        }
        break;
    }
    }

    return {};
}

std::expected<entt::id_type, std::string_view>
check_node_schema(const entt::registry& r, const nlohmann::json& node) noexcept {
    if (!node.contains("type"sv)) {
        return std::unexpected("missing node type");
    }

    const auto type = hash(node["type"sv].get<std::string>());

    const auto* node_schema = get_node_schema(r, type);
    if (node_schema == nullptr) {
        return std::unexpected("unknown node type"sv);
    }

    graph::small_vector<bool, max_properties> found;
    found.resize(node_schema->properties.size());

    if (node.contains("properties"sv)) {
        for (const auto& [k, v] : node["properties"sv].items()) {
            const auto* property_schema = get_property_schema(*node_schema, hash(k));
            if (property_schema == nullptr) {
                return std::unexpected("unknown property"sv);
            }

            const std::size_t property_id = property_schema - node_schema->properties.data();
            if (found[property_id]) {
                return std::unexpected("duplicate property");
            }

            found[property_id] = true;

            if (auto s = check_property_schema(*property_schema, v); !s) {
                return std::unexpected(s.error());
            }
        }
    }

    if (!std::all_of(found.begin(), found.end(), [](bool b) { return b; })) {
        return std::unexpected("missing property");
    }

    return type;
}

template<typename Item>
nlohmann::json save_schema_item(const Item& n) {
    nlohmann::json data(nlohmann::json::value_t::object);

    if (!n.properties.empty()) {
        nlohmann::json properties(nlohmann::json::value_t::object);
        for (const auto& p : n.properties) {
            properties[p.name.str.str()] = p.type.str.str();
        }

        data["properties"sv] = std::move(properties);
    }

    return data;
}

nlohmann::json save_schema_link(const schema_link& l) {
    nlohmann::json data = save_schema_item(l);
    data["source"sv]    = l.source.str.str();
    data["target"sv]    = l.target.str.str();

    return data;
}
} // namespace

namespace graph {
void load_schema(entt::registry& r, const nlohmann::json& data) {
    schema s;

    if (data.contains("nodes"sv)) {
        for (const auto& [k, v] : data["nodes"sv].items()) {
            load_schema_item(s.nodes, k, v);
        }

        std::sort(s.nodes.begin(), s.nodes.end(), type_less{});
    }

    if (data.contains("links"sv)) {
        for (const auto& [k, v] : data["links"sv].items()) {
            load_schema_link(s.links, k, v);
        }

        std::sort(s.links.begin(), s.links.end(), type_less{});
    }

    r.ctx().erase<schema>();
    r.ctx().emplace<schema>(std::move(s));
}

nlohmann::json save_schema(const entt::registry& r) {
    const auto& s = r.ctx().get<schema>();

    nlohmann::json data(nlohmann::json::value_t::object);

    {
        nlohmann::json nodes(nlohmann::json::value_t::object);
        for (const auto& n : s.nodes) {
            nodes[n.type.str.str()] = save_schema_item(n);
        }

        data["nodes"sv] = std::move(nodes);
    }

    {
        nlohmann::json links(nlohmann::json::value_t::object);
        for (const auto& l : s.links) {
            links[l.type.str.str()] = save_schema_link(l);
        }

        data["links"sv] = std::move(links);
    }

    return data;
}

std::expected<entt::entity, std::string_view>
add_node(entt::registry& r, const nlohmann::json& node) {
    // Validate against schema.
    auto type = check_node_schema(r, node);
    if (!type) {
        return std::unexpected(type.error());
    }

    // From now on, parsing success is guaranteed, we can commit the data.
    // Exceptions may still be thrown when out-of-memory, or entity cap reached.
    // So wrap all in try/catch target cancel on failure. These should be rare.
    entt::entity e = entt::null;
    try {
        e = r.create();
        r.emplace<node_type>(e, node_type{.type = type.value()});

        for (const auto& [k, v] : node["properties"].items()) {
            // TODO: Add new node
            // switch (v.type()) {
            // }
            // auto& s = r.storage<T>(hash(k));
            // s.emplace(e, ...);
        }
    } catch (...) {
        if (e != entt::null) {
            r.destroy(e);
        }
        throw;
    }

    return e;
}
} // namespace graph
