#include "graph/graph.hpp"
#include "graph/graph_vector.hpp"
#include "graph/graph_string.hpp"

using namespace entt::literals;
using namespace std::literals;

namespace {
struct node_type {
    entt::id_type type{};
};

struct link_type {
    entt::id_type type{};
};

struct schema_property {
    entt::id_type name{};
    entt::id_type type{};
};

struct schema_node {
    entt::id_type type{};
    graph::small_vector<schema_property, 16> properties{};
};

struct schema_link {
    entt::id_type type{};
    entt::id_type from{};
    entt::id_type to{};
    graph::small_vector<schema_property, 16> properties{};
};

struct schema {
    graph::small_vector<schema_node, 32> nodes{};
    graph::small_vector<schema_link, 32> links{};
};

entt::id_type hash(std::string_view s) noexcept {
    return entt::hashed_string::value(s.data(), s.size());
}

template<typename Item>
schema_property& load_schema_property(Item& r, std::string_view name, const nlohmann::json& data) {
    return r.properties.push_back({.name=hash(name), .type=hash(data.get<std::string>())});
}

template<typename Storage>
auto& load_schema_item(Storage& r, std::string_view name, const nlohmann::json& data) {
    typename Storage::value_type item{.type = hash(name)};
    for (const auto& [k,v] : data.items()) {
        if (std::string_view(k).starts_with("__")) { continue; }
        load_schema_property(item, k, v);
    }

    return r.push_back(item);
}

template<typename Storage>
auto& load_schema_link(Storage& r, std::string_view name, const nlohmann::json& data) {
    auto& l = load_schema_item(r, name, data);
    l.from = hash(data["__from"sv].get<std::string>());
    l.to = hash(data["__to"sv].get<std::string>());

    return l;
}

struct type_less {
    static entt::id_type get_type(const auto& n) noexcept {
        return n.type;
    }

    static entt::id_type get_type(entt::id_type t) noexcept {
        return t;
    }

    bool operator()(const auto& n1, const auto& n2) const noexcept {
        return get_type(n1) < get_type(n2);
    }
};

const schema_node* get_node_schema(const entt::registry& r, entt::id_type type) noexcept {
    const auto& s = r.ctx().get<schema>();
    auto iter = std::lower_bound(s.nodes.begin(), s.nodes.end(), type, type_less{});
    if (iter == s.nodes.end() || iter->type != type) {
        return nullptr;
    }

    return &*iter;
}

const schema_link* get_link_schema(const entt::registry& r, entt::id_type type) noexcept {
    const auto& s = r.ctx().get<schema>();
    auto iter = std::lower_bound(s.links.begin(), s.links.end(), type, type_less{});
    if (iter == s.links.end() || iter->type != type) {
        return nullptr;
    }

    return &*iter;
}

template<typename Item>
const schema_property* get_property_schema(const Item& n, entt::id_type name) noexcept {
    auto iter = std::find_if(n.properties.begin(), n.properties.end(), [&](const schema_property& p) {
        return p.name == name;
    });

    if (iter == n.properties.end()) {
        return nullptr;
    }

    return &*iter;
}

bool check_property_schema(const schema_property& s, const nlohmann::json& p) noexcept {
    switch (s.type) {
    case "string"_hs: {
        if (!p.is_string()) {
            return false;
        }
    }
    case "integer"_hs: {
        if (!p.is_number_integer()) {
            return false;
        }
    }
    case "float"_hs: {
        if (!p.is_number_float()) {
            return false;
        }
    }
    case "bool"_hs: {
        if (!p.is_boolean()) {
            return false;
        }
    }
    }

    return true;
}
}

namespace graph {
void load_schema(entt::registry& r, const nlohmann::json& data) {
    auto& s = r.ctx().emplace<schema>();

    for (const auto& [k,v] : data["nodes"sv].items()) {
        load_schema_item(s.nodes, k, v);
    }

    std::sort(s.nodes.begin(), s.nodes.end(), type_less{});

    for (const auto& [k,v] : data["links"sv].items()) {
        load_schema_link(s.links, k, v);
    }

    std::sort(s.links.begin(), s.links.end(), type_less{});
}

bool add_node(entt::registry& r, const nlohmann::json& node) {
    const auto e = r.create();

    // Validate against schema.
    const auto type = hash(node["type"sv].get<std::string>());
    const auto* node_schema = get_node_schema(r, type);
    if (node_schema == nullptr) {
        return false;
    }

    for (const auto& [k,v] : node.items()) {
        if (k == "type"sv) { continue; }

        const auto* property_schema = get_property_schema(*node_schema, hash(k));
        if (property_schema == nullptr) {
            return false;
        }

        if (!check_property_schema(*property_schema, v)) {
            return false;
        }
    }

    // From now on, success is guaranteed, we can commit the data.
    r.emplace<node_type>(e, node_type{.type=type});

    for (const auto& [k,v] : node.items()) {
        if (k == "type"sv) { continue; }

        // TODO: Add new node
        // switch (v.type()) {
        // }
        // auto& s = r.storage<T>(hash(k));
        // s.emplace(e, ...);
    }

    return true;
}
}
