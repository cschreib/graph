#include "graph/graph.hpp"

#include "graph/graph_string.hpp"
#include "graph/graph_vector.hpp"

#include <algorithm>
#include <charconv>

using namespace entt::literals;
using namespace std::literals;

namespace {
constexpr std::size_t max_properties                      = 16;
constexpr std::size_t max_schema_nodes                    = 32;
constexpr std::size_t max_schema_relationships            = 32;
constexpr std::size_t max_string_id_length                = 32;
constexpr std::size_t max_in_place_string_property_length = 128;

using graph::entity;
using graph::expected;
using graph::json;
using graph::registry;

using hash_data_t = std::uint64_t;
enum class hash_t : hash_data_t {};

constexpr hash_data_t hash_offset = 14695981039346656037ull;
constexpr hash_data_t hash_prime  = 1099511628211ull;

template<typename T>
[[nodiscard]] constexpr hash_t
hash_buffer(hash_t hash_in, const T* data, std::size_t length) noexcept {
    static_assert(sizeof(T) == 1);

    hash_data_t hash = static_cast<hash_data_t>(hash_in);

    for (std::size_t i = 0; i < length; ++i) {
        hash = (hash ^ static_cast<hash_data_t>(data[i])) * hash_prime;
    }

    return static_cast<hash_t>(hash);
}

template<typename T>
[[nodiscard]] constexpr hash_t hash_buffer(const T* data, std::size_t length) noexcept {
    return hash_buffer(static_cast<hash_t>(hash_offset), data, length);
}

[[nodiscard]] constexpr hash_t operator"" _h64(const char* str, std::size_t len) noexcept {
    return hash_buffer(str, len);
}

struct hashed_string {
    hash_t                                    hash{};
    graph::small_string<max_string_id_length> data{};

    std::string_view str() const noexcept {
        return data.str();
    }
};

struct string_property {
    std::variant<graph::small_string<max_in_place_string_property_length>, std::string> value;

    explicit string_property(std::string_view s) {
        if (s.size() <= max_in_place_string_property_length) {
            value.emplace<graph::small_string<max_in_place_string_property_length>>(s);
        } else {
            value.emplace<std::string>(s);
        }
    }
};

void to_json(json& j, const string_property& s) {
    std::visit(
        [&](const auto& v) {
            if constexpr (std::is_same_v<std::decay_t<decltype(v)>, std::string>) {
                j = v;
            } else {
                j = v.str();
            }
        },
        s.value);
}

using property_type = std::variant<bool, std::int64_t, double, string_property>;

struct node_base {
    hash_t type{};
};

struct relationship_base {
    hash_t type{};
    entity source = entt::null;
    entity target = entt::null;
};

struct schema_property {
    hashed_string name{};
    hashed_string type{};
};

struct schema_node {
    hashed_string                                        type{};
    graph::small_vector<schema_property, max_properties> properties{};
};

struct schema_relationship {
    hashed_string                                        type{};
    hashed_string                                        source{};
    hashed_string                                        target{};
    graph::small_vector<schema_property, max_properties> properties{};
};

struct schema_graph {
    graph::small_vector<schema_node, max_schema_nodes>                 nodes{};
    graph::small_vector<schema_relationship, max_schema_relationships> relationships{};
};

hash_t hash(std::string_view s) noexcept {
    return hash_buffer(s.data(), s.size());
}

hash_t hash(std::string_view s1, std::string_view s2) noexcept {
    auto h = hash_buffer(s1.data(), s1.size());
    h      = hash_buffer(h, "|", 1u);
    h      = hash_buffer(h, s2.data(), s2.size());
    return h;
}

hash_t hash(hash_t h1, std::string_view s2) noexcept {
    auto h = h1;
    h      = hash_buffer(h, "|", 1u);
    h      = hash_buffer(h, s2.data(), s2.size());
    return h;
}

hashed_string add_hash(std::string_view s) noexcept {
    return hashed_string{.hash = hash(s), .data = s};
}

hashed_string add_hash(std::string_view base, std::string_view element) noexcept {
    return hashed_string{.hash = hash(base, element), .data = element};
}

hashed_string add_hash(hash_t base_hash, std::string_view element) noexcept {
    return hashed_string{.hash = hash(base_hash, element), .data = element};
}

template<typename Item>
schema_property&
load_schema_property(Item& r, std::string_view node_name, std::string_view name, const json& data) {
    return r.properties.push_back(
        {.name = add_hash(node_name, name), .type = add_hash(data.get<std::string>())});
}

template<typename Storage>
auto& load_schema_item(Storage& r, std::string_view name, const json& data) {
    typename Storage::value_type item{.type = add_hash(name)};
    if (data.contains("properties"sv)) {
        for (const auto& [k, v] : data["properties"sv].items()) {
            load_schema_property(item, name, k, v);
        }
    }

    return r.push_back(item);
}

template<typename Storage>
expected<std::reference_wrapper<typename Storage::value_type>>
load_schema_relationship(Storage& r, std::string_view name, const json& data) {
    if (!data.contains("source"sv)) {
        return std::unexpected("missing source"sv);
    }
    if (!data.contains("target"sv)) {
        return std::unexpected("missing target"sv);
    }

    auto& l = load_schema_item(r, name, data);

    l.source = add_hash(data["source"sv].get<std::string>());
    l.target = add_hash(data["target"sv].get<std::string>());

    return l;
}

struct type_less {
    static hash_t get_type(const auto& n) noexcept {
        return n.type.hash;
    }

    static hash_t get_type(hash_t s) noexcept {
        return s;
    }

    bool operator()(const auto& n1, const auto& n2) const noexcept {
        return get_type(n1) < get_type(n2);
    }
};

const schema_node* try_get_node_schema(const registry& r, hash_t type) noexcept {
    const auto& schema = r.ctx().get<schema_graph>();
    auto iter = std::lower_bound(schema.nodes.begin(), schema.nodes.end(), type, type_less{});
    if (iter == schema.nodes.end() || iter->type.hash != type) {
        return nullptr;
    }

    return &*iter;
}

const schema_node& get_node_schema(const registry& r, hash_t type) noexcept {
    const auto* schema = try_get_node_schema(r, type);
    if (schema == nullptr) {
        graph::terminate_with("unknown node type"sv);
    }

    return *schema;
}

expected<std::reference_wrapper<const node_base>> get_node_props(const registry& r, entity node) {
    if (!r.valid(node)) {
        return std::unexpected("node does not exist"sv);
    }

    const auto* node_props = r.try_get<node_base>(node);
    if (node_props == nullptr) {
        return std::unexpected("not a node"sv);
    }

    return *node_props;
}

expected<std::reference_wrapper<const schema_node>>
get_node_schema(const registry& r, entity node) {
    const auto node_props = get_node_props(r, node);
    if (!node_props) {
        return std::unexpected(node_props.error());
    }

    const auto type = node_props.value().get().type;
    return get_node_schema(r, type);
}

const schema_relationship* try_get_relationship_schema(const registry& r, hash_t type) noexcept {
    const auto& schema = r.ctx().get<schema_graph>();
    auto        iter   = std::lower_bound(
        schema.relationships.begin(), schema.relationships.end(), type, type_less{});
    if (iter == schema.relationships.end() || iter->type.hash != type) {
        return nullptr;
    }

    return &*iter;
}

const schema_relationship& get_relationship_schema(const registry& r, hash_t type) noexcept {
    const auto* schema = try_get_relationship_schema(r, type);
    if (schema == nullptr) {
        graph::terminate_with("unknown relationship type"sv);
    }

    return *schema;
}

expected<std::reference_wrapper<const relationship_base>>
get_relationship_props(const registry& r, entity relationship) {
    if (!r.valid(relationship)) {
        return std::unexpected("relationship does not exist"sv);
    }

    const auto* relationship_props = r.try_get<relationship_base>(relationship);
    if (relationship_props == nullptr) {
        return std::unexpected("not a relationship"sv);
    }

    return *relationship_props;
}

expected<std::reference_wrapper<const schema_relationship>>
get_relationship_schema(const registry& r, entity relationship) {
    const auto relationship_props = get_relationship_props(r, relationship);
    if (!relationship_props) {
        return std::unexpected(relationship_props.error());
    }

    return get_relationship_schema(r, relationship_props.value().get().type);
}

template<typename Item>
const schema_property* try_get_property_schema(const Item& n, hash_t name) noexcept {
    auto iter =
        std::find_if(n.properties.begin(), n.properties.end(), [&](const schema_property& p) {
            return p.name.hash == name;
        });

    if (iter == n.properties.end()) {
        return nullptr;
    }

    return &*iter;
}

template<typename Item>
const schema_property& get_property_schema(const Item& n, hash_t name) noexcept {
    const auto* schema = try_get_property_schema(n, name);
    if (schema == nullptr) {
        graph::terminate_with("unknown property"sv);
    }

    return *schema;
}

expected<void> check_property_schema(const schema_property& schema, const json& p) noexcept {
    switch (schema.type.hash) {
    case "string"_h64: {
        if (!p.is_string()) {
            return std::unexpected("expected string value"sv);
        }
        break;
    }
    case "integer"_h64: {
        if (!p.is_number_integer()) {
            return std::unexpected("expected integer value"sv);
        }
        break;
    }
    case "float"_h64: {
        if (!p.is_number_float()) {
            return std::unexpected("expected float value"sv);
        }
        break;
    }
    case "bool"_h64: {
        if (!p.is_boolean()) {
            return std::unexpected("expected boolean value"sv);
        }
        break;
    }
    default: graph::terminate_with("unsupported type"sv);
    }

    return {};
}

template<typename Schema>
expected<void>
check_item_property_schema(const registry& r, const Schema& schema, const json& item) noexcept {
    graph::small_vector<bool, max_properties> found;
    found.resize(schema.properties.size());

    if (item.contains("properties"sv)) {
        for (const auto& [k, v] : item["properties"sv].items()) {
            const auto* property_schema =
                try_get_property_schema(schema, hash(schema.type.hash, k));
            if (property_schema == nullptr) {
                return std::unexpected("unknown property"sv);
            }

            const std::size_t property_id = property_schema - schema.properties.data();
            if (found[property_id]) {
                return std::unexpected("duplicate property"sv);
            }

            found[property_id] = true;

            if (auto s = check_property_schema(*property_schema, v); !s) {
                return std::unexpected(s.error());
            }
        }
    }

    if (!std::all_of(found.begin(), found.end(), [](bool b) { return b; })) {
        return std::unexpected("missing property"sv);
    }

    return {};
}

struct validated_node {
    hash_t             type;
    const schema_node& schema;
};

expected<validated_node> check_node_schema(const registry& r, const json& node) noexcept {
    if (!node.contains("type"sv)) {
        return std::unexpected("missing node type"sv);
    }

    const auto* schema = try_get_node_schema(r, hash(node["type"sv].get<std::string>()));
    if (schema == nullptr) {
        return std::unexpected("unknown node type"sv);
    }

    if (auto s = check_item_property_schema(r, *schema, node); !s) {
        return std::unexpected(s.error());
    }

    return validated_node{.type = schema->type.hash, .schema = *schema};
}

struct validated_relationship {
    hash_t                     type{};
    entity                     source{};
    entity                     target{};
    const schema_relationship& schema;
};

expected<validated_relationship>
check_relationship_schema(const registry& r, const json& relationship) noexcept {
    if (!relationship.contains("type"sv)) {
        return std::unexpected("missing relationship type"sv);
    }

    if (!relationship.contains("source"sv)) {
        return std::unexpected("missing relationship source"sv);
    }

    if (!relationship.contains("target"sv)) {
        return std::unexpected("missing relationship target"sv);
    }

    const auto* schema =
        try_get_relationship_schema(r, hash(relationship["type"sv].get<std::string>()));
    if (schema == nullptr) {
        return std::unexpected("unknown relationship type"sv);
    }

    const auto source = graph::id_from_string(relationship["source"sv].get<std::string>());
    if (!source) {
        return std::unexpected(source.error());
    }

    if (!r.valid(source.value())) {
        return std::unexpected("source does not exist"sv);
    }

    const auto* source_props = r.try_get<node_base>(source.value());
    if (source_props == nullptr) {
        return std::unexpected("source is not a node"sv);
    }

    if (source_props->type != schema->source.hash) {
        return std::unexpected("source has incorrect type"sv);
    }

    const auto target = graph::id_from_string(relationship["target"sv].get<std::string>());
    if (!target) {
        return std::unexpected(target.error());
    }

    if (!r.valid(target.value())) {
        return std::unexpected("target does not exist"sv);
    }

    const auto* target_props = r.try_get<node_base>(target.value());
    if (target_props == nullptr) {
        return std::unexpected("target is not a node"sv);
    }

    if (target_props->type != schema->target.hash) {
        return std::unexpected("target has incorrect type"sv);
    }

    if (auto s = check_item_property_schema(r, *schema, relationship); !s) {
        return std::unexpected(s.error());
    }

    return validated_relationship{
        .type   = schema->type.hash,
        .source = source.value(),
        .target = target.value(),
        .schema = *schema};
}

template<typename Validated>
void add_properties(registry& r, entity e, const Validated& validated, const json& data) {
    if (!data.contains("properties"sv)) {
        return;
    }

    for (const auto& [k, v] : data["properties"sv].items()) {
        const auto  name_hash       = hash(validated.type, k);
        const auto& property_schema = get_property_schema(validated.schema, name_hash);
        add_property(r, e, property_schema, v);
    }
}

template<typename Item>
json save_schema_item(const Item& n) {
    json data(json::value_t::object);

    if (!n.properties.empty()) {
        json properties(json::value_t::object);
        for (const auto& p : n.properties) {
            properties[p.name.str()] = p.type.str();
        }

        data["properties"sv] = std::move(properties);
    }

    return data;
}

json save_schema_relationship(const schema_relationship& l) {
    json data        = save_schema_item(l);
    data["source"sv] = l.source.str();
    data["target"sv] = l.target.str();

    return data;
}

void add_tag(registry& r, entity e, hash_t tag) {
    static_assert(sizeof(entt::id_type) == sizeof(hash_data_t));
    auto& s = r.storage<std::monostate>(static_cast<entt::id_type>(tag));
    s.emplace(e);
}

template<typename Registry>
auto view_nodes(Registry& r, hash_t type) {
    static_assert(sizeof(entt::id_type) == sizeof(hash_data_t));
    return r.template view<node_base>() |
           entt::basic_view{r.template storage<std::monostate>(static_cast<entt::id_type>(type))};
}

template<typename Registry>
auto view_relationships(Registry& r, hash_t type) {
    static_assert(sizeof(entt::id_type) == sizeof(hash_data_t));
    return r.template view<relationship_base>() |
           entt::basic_view{r.template storage<std::monostate>(static_cast<entt::id_type>(type))};
}

template<typename StorageType>
void add_property(registry& r, entity e, hash_t name_hash, const StorageType& value) {
    static_assert(sizeof(entt::id_type) == sizeof(hash_data_t));
    auto& s = r.storage<StorageType>(static_cast<entt::id_type>(name_hash));
    s.emplace(e, value);
}

void add_property(registry& r, entity e, const schema_property& schema, const json& value) {
    switch (schema.type.hash) {
    case "string"_h64: {
        add_property(r, e, schema.name.hash, string_property(value.get<std::string>()));
        break;
    }
    case "integer"_h64: {
        add_property(r, e, schema.name.hash, value.get<std::int64_t>());
        break;
    }
    case "float"_h64: {
        add_property(r, e, schema.name.hash, value.get<double>());
        break;
    }
    case "bool"_h64: {
        add_property(r, e, schema.name.hash, value.get<bool>());
        break;
    }
    default: graph::terminate_with("unsupported type"sv);
    }
}

template<typename StorageType>
property_type get_property(const registry& r, entity e, hash_t name_hash) {
    static_assert(sizeof(entt::id_type) == sizeof(hash_data_t));
    const auto& s = r.storage<StorageType>(static_cast<entt::id_type>(name_hash));
    return s.get(e);
}

property_type get_property(const registry& r, entity e, const schema_property& schema) {
    switch (schema.type.hash) {
    case "string"_h64: {
        return get_property<string_property>(r, e, schema.name.hash);
        break;
    }
    case "integer"_h64: {
        return get_property<std::int64_t>(r, e, schema.name.hash);
        break;
    }
    case "float"_h64: {
        return get_property<double>(r, e, schema.name.hash);
        break;
    }
    case "bool"_h64: {
        return get_property<bool>(r, e, schema.name.hash);
        break;
    }
    default: graph::terminate_with("unsupported type"sv);
    }
}

template<typename Schema>
expected<json>
get_property(const registry& r, entity item, const Schema& schema, std::string_view property) {
    const auto  property_hash   = hash(schema.type.hash, property);
    const auto* property_schema = try_get_property_schema(schema, property_hash);
    if (!property_schema) {
        return std::unexpected("unknown property"sv);
    }

    const auto p = get_property(r, item, *property_schema);
    return std::visit([](const auto& pv) { return json(pv); }, p);
}

template<typename Schema>
expected<json> get_properties(const registry& r, entity item, const Schema& schema) {
    json data(json::value_t::object);

    for (const auto& property_schema : schema.properties) {
        const auto p = get_property(r, item, property_schema);
        std::visit([&](const auto& pv) { data[property_schema.name.str()] = json(pv); }, p);
    }

    return data;
}

void dump_nodes(const registry& r, const schema_node& schema, json& data) {
    auto view = view_nodes(r, schema.type.hash);
    for (auto e : view) {
        json node(json::value_t::object);
        node["type"sv] = schema.type.str();
        if (!schema.properties.empty()) {
            node["properties"sv] = graph::get_node_properties(r, e).value();
        }
        data[graph::id_to_string(e).str()] = std::move(node);
    }
}

void dump_relationships(const registry& r, const schema_relationship& schema, json& data) {
    auto view = view_relationships(r, schema.type.hash);
    for (auto e : view) {
        const auto& rs = view.get<relationship_base>(e);

        json relationship(json::value_t::object);
        relationship["type"sv]   = schema.type.str();
        relationship["source"sv] = graph::id_to_string(rs.source);
        relationship["target"sv] = graph::id_to_string(rs.target);
        if (!schema.properties.empty()) {
            relationship["properties"sv] = graph::get_relationship_properties(r, e).value();
        }
        data[graph::id_to_string(e).str()] = std::move(relationship);
    }
}
} // namespace

namespace graph {
small_string<32> id_to_string(entity e) noexcept {
    small_string<32> buffer;
    auto             res = std::to_chars(
        buffer.data(), buffer.data() + buffer.capacity(), static_cast<std::uint64_t>(e));
    buffer.resize(res.ptr - buffer.data());
    return buffer;
}

expected<entity> id_from_string(std::string_view s) noexcept {
    static_assert(sizeof(entity) == sizeof(std::uint64_t));

    std::uint64_t i   = 0u;
    auto          res = std::from_chars(s.begin(), s.end(), i);
    if (res.ptr == s.begin()) {
        return std::unexpected("ID is not a valid number");
    }

    return static_cast<entity>(i);
}

expected<void> load_schema(registry& r, const json& data) {
    if (r.alive() > 0) {
        return std::unexpected(
            "cannot load a new schema in a registry that already contains entities"sv);
    }

    schema_graph schema;

    if (data.contains("nodes"sv)) {
        for (const auto& [k, v] : data["nodes"sv].items()) {
            load_schema_item(schema.nodes, k, v);
        }

        std::sort(schema.nodes.begin(), schema.nodes.end(), type_less{});
    }

    if (data.contains("relationships"sv)) {
        for (const auto& [k, v] : data["relationships"sv].items()) {
            auto res = load_schema_relationship(schema.relationships, k, v);
            if (!res) {
                return std::unexpected(res.error());
            }
        }

        std::sort(schema.relationships.begin(), schema.relationships.end(), type_less{});
    }

    r.ctx().erase<schema_graph>();
    r.ctx().emplace<schema_graph>(std::move(schema));

    return {};
}

json dump_schema(const registry& r) {
    const auto& schema = r.ctx().get<schema_graph>();

    json data(json::value_t::object);

    {
        json nodes(json::value_t::object);
        for (const auto& n : schema.nodes) {
            nodes[n.type.str()] = save_schema_item(n);
        }

        data["nodes"sv] = std::move(nodes);
    }

    {
        json relationships(json::value_t::object);
        for (const auto& l : schema.relationships) {
            relationships[l.type.str()] = save_schema_relationship(l);
        }

        data["relationships"sv] = std::move(relationships);
    }

    return data;
}

expected<void> load_nodes(registry& r, const json& nodes) {
    if (nodes.type() != json::value_t::object) {
        return std::unexpected("nodes must be an object");
    }

    for (const auto& [e, n] : nodes.items()) {
        const auto id = id_from_string(e);
        if (!id) {
            return std::unexpected(id.error());
        }

        auto result = add_node(r, id.value(), n);
        if (!result) {
            return std::unexpected(result.error());
        }
    }

    return {};
}

json dump_nodes(const registry& r) {
    const auto& graph_schema = r.ctx().get<schema_graph>();

    json data(json::value_t::object);
    for (const auto& node_schema : graph_schema.nodes) {
        dump_nodes(r, node_schema, data);
    }

    return data;
}

expected<void> load_relationships(registry& r, const json& relationships) {
    if (relationships.type() != json::value_t::object) {
        return std::unexpected("relationships must be an object");
    }

    for (const auto& [e, rs] : relationships.items()) {
        const auto id = id_from_string(e);
        if (!id) {
            return std::unexpected(id.error());
        }

        auto result = add_relationship(r, id.value(), rs);
        if (!result) {
            return std::unexpected(result.error());
        }
    }

    return {};
}

json dump_relationships(const registry& r) {
    const auto& graph_schema = r.ctx().get<schema_graph>();

    json data(json::value_t::object);

    for (const auto& relationship_schema : graph_schema.relationships) {
        dump_relationships(r, relationship_schema, data);
    }

    return data;
}

expected<void> load(registry& r, const json& data) {
    if (!data.contains("schema"sv)) {
        return std::unexpected("missing schema"sv);
    }

    {
        auto chk = load_schema(r, data["schema"sv]);
        if (!chk) {
            return std::unexpected(chk.error());
        }
    }

    if (data.contains("nodes"sv)) {
        auto chk = load_nodes(r, data["nodes"sv]);
        if (!chk) {
            return std::unexpected(chk.error());
        }
    }

    if (data.contains("relationships"sv)) {
        auto chk = load_relationships(r, data["relationships"sv]);
        if (!chk) {
            return std::unexpected(chk.error());
        }
    }

    return {};
}

json dump(const registry& r) {
    json data(json::value_t::object);
    data["schema"sv]        = dump_schema(r);
    data["nodes"sv]         = dump_nodes(r);
    data["relationships"sv] = dump_relationships(r);
    return data;
}

expected<entity> add_node(registry& r, const json& node) {
    // Validate against schema.
    const auto validated_chk = check_node_schema(r, node);
    if (!validated_chk) {
        return std::unexpected(validated_chk.error());
    }

    const auto& validated = validated_chk.value();

    // From now on, parsing success is guaranteed, we can commit the data.
    // Exceptions may still be thrown when out-of-memory, or entity cap reached.
    // So wrap all in try/catch to cancel on failure. These should be rare.
    entity e = r.create();
    try {
        r.emplace<node_base>(e, node_base{.type = validated.type});
        add_tag(r, e, validated.type);
        add_properties(r, e, validated, node);
    } catch (...) {
        r.destroy(e);
        throw;
    }

    return e;
}

expected<entity> add_node(registry& r, entity e, const json& node) {
    // Validate against schema.
    const auto validated_chk = check_node_schema(r, node);
    if (!validated_chk) {
        return std::unexpected(validated_chk.error());
    }

    const auto& validated = validated_chk.value();

    // From now on, parsing success is guaranteed, we can commit the data.
    // Exceptions may still be thrown when out-of-memory, or entity cap reached.
    // So wrap all in try/catch to cancel on failure. These should be rare.
    auto enew = r.create(e);
    if (enew != e) {
        r.destroy(enew);
        return std::unexpected("node ID already in use");
    }

    try {
        r.emplace<node_base>(e, node_base{.type = validated.type});
        add_tag(r, e, validated.type);
        add_properties(r, e, validated, node);
    } catch (...) {
        r.destroy(e);
        throw;
    }

    return e;
}

expected<entity> add_relationship(registry& r, const json& relationship) {
    // Validate against schema.
    const auto validated_chk = check_relationship_schema(r, relationship);
    if (!validated_chk) {
        return std::unexpected(validated_chk.error());
    }

    const auto& validated = validated_chk.value();

    // From now on, parsing success is guaranteed, we can commit the data.
    // Exceptions may still be thrown when out-of-memory, or entity cap reached.
    // So wrap all in try/catch to cancel on failure. These should be rare.
    entity e = r.create();
    try {
        r.emplace<relationship_base>(
            e, relationship_base{
                   .type = validated.type, .source = validated.source, .target = validated.target});
        add_tag(r, e, validated.type);
        add_properties(r, e, validated, relationship);
    } catch (...) {
        r.destroy(e);
        throw;
    }

    return e;
}

expected<entity> add_relationship(registry& r, entity e, const json& relationship) {
    // Validate against schema.
    const auto validated_chk = check_relationship_schema(r, relationship);
    if (!validated_chk) {
        return std::unexpected(validated_chk.error());
    }

    const auto& validated = validated_chk.value();

    // From now on, parsing success is guaranteed, we can commit the data.
    // Exceptions may still be thrown when out-of-memory, or entity cap reached.
    // So wrap all in try/catch to cancel on failure. These should be rare.
    auto enew = r.create(e);
    if (enew != e) {
        r.destroy(enew);
        return std::unexpected("relationship ID already in use");
    }

    try {
        r.emplace<relationship_base>(
            e, relationship_base{
                   .type = validated.type, .source = validated.source, .target = validated.target});
        add_tag(r, e, validated.type);
        add_properties(r, e, validated, relationship);
    } catch (...) {
        r.destroy(e);
        throw;
    }

    return e;
}

expected<std::string_view> get_node_type(const registry& r, entity node) {
    const auto node_schema_chk = get_node_schema(r, node);
    if (!node_schema_chk) {
        return std::unexpected(node_schema_chk.error());
    }

    return node_schema_chk.value().get().type.str();
}

expected<std::string_view> get_relationship_type(const registry& r, entity relationship) {
    const auto relationship_schema_chk = get_relationship_schema(r, relationship);
    if (!relationship_schema_chk) {
        return std::unexpected(relationship_schema_chk.error());
    }

    return relationship_schema_chk.value().get().type.str();
}

expected<entity> get_relationship_target(const registry& r, entity relationship) {
    const auto relationship_props_chk = get_relationship_props(r, relationship);
    if (!relationship_props_chk) {
        return std::unexpected(relationship_props_chk.error());
    }

    return relationship_props_chk.value().get().target;
}

expected<entity> get_relationship_source(const registry& r, entity relationship) {
    const auto relationship_props_chk = get_relationship_props(r, relationship);
    if (!relationship_props_chk) {
        return std::unexpected(relationship_props_chk.error());
    }

    return relationship_props_chk.value().get().source;
}

expected<json> get_node_property(const registry& r, entity node, std::string_view property) {
    const auto node_schema_chk = get_node_schema(r, node);
    if (!node_schema_chk) {
        return std::unexpected(node_schema_chk.error());
    }

    return get_property(r, node, node_schema_chk.value().get(), property);
}

expected<json>
get_relationship_property(const registry& r, entity relationship, std::string_view property) {
    const auto relationship_schema_chk = get_relationship_schema(r, relationship);
    if (!relationship_schema_chk) {
        return std::unexpected(relationship_schema_chk.error());
    }

    return get_property(r, relationship, relationship_schema_chk.value().get(), property);
}

expected<json> get_node_properties(const registry& r, entity node) {
    const auto node_schema_chk = get_node_schema(r, node);
    if (!node_schema_chk) {
        return std::unexpected(node_schema_chk.error());
    }

    return get_properties(r, node, node_schema_chk.value().get());
}

expected<json> get_relationship_properties(const registry& r, entity relationship) {
    const auto relationship_schema_chk = get_relationship_schema(r, relationship);
    if (!relationship_schema_chk) {
        return std::unexpected(relationship_schema_chk.error());
    }

    return get_properties(r, relationship, relationship_schema_chk.value().get());
}

expected<json> get_node_relationships(const registry& r, entity node) {
    const auto node_schema_chk = get_node_schema(r, node);
    if (!node_schema_chk) {
        return std::unexpected(node_schema_chk.error());
    }

    const auto& node_schema  = node_schema_chk.value().get();
    const auto& graph_schema = r.ctx().get<schema_graph>();

    json data(json::value_t::array);

    for (const auto& relationship_schema : graph_schema.relationships) {
        if (relationship_schema.source.hash != node_schema.type.hash &&
            relationship_schema.target.hash != node_schema.type.hash) {
            continue;
        }

        auto view = view_relationships(r, relationship_schema.type.hash);
        for (auto relationship : view) {
            const auto& relationship_props = view.get<relationship_base>(relationship);
            if (relationship_props.source == node || relationship_props.target == node) {
                data.push_back(relationship);
            }
        }
    }

    return data;
}

expected<json> get_node_relationships(const registry& r, entity node, std::string_view type) {
    const auto node_schema_chk = get_node_schema(r, node);
    if (!node_schema_chk) {
        return std::unexpected(node_schema_chk.error());
    }

    const auto& node_schema         = node_schema_chk.value().get();
    const auto* relationship_schema = try_get_relationship_schema(r, hash(type));
    if (relationship_schema == nullptr) {
        return std::unexpected("unknown relationship type"sv);
    }

    if (relationship_schema->source.hash != node_schema.type.hash &&
        relationship_schema->target.hash != node_schema.type.hash) {
        return std::unexpected("this node cannot have this relationship"sv);
    }

    json data(json::value_t::array);

    auto view = view_relationships(r, relationship_schema->type.hash);
    for (auto relationship : view) {
        const auto& relationship_props = view.get<relationship_base>(relationship);
        if (relationship_props.source == node || relationship_props.target == node) {
            data.push_back(relationship);
        }
    }

    return data;
}

expected<json> get_nodes(const registry& r, std::string_view type) {
    const auto* schema = try_get_node_schema(r, hash(type));
    if (schema == nullptr) {
        graph::terminate_with("unknown node type"sv);
    }

    json data(json::value_t::object);
    dump_nodes(r, *schema, data);
    return data;
}

expected<json> get_relationships(const registry& r, std::string_view type) {
    const auto* schema = try_get_relationship_schema(r, hash(type));
    if (schema == nullptr) {
        graph::terminate_with("unknown relationship type"sv);
    }

    json data(json::value_t::object);
    dump_relationships(r, *schema, data);
    return data;
}

expected<void> delete_node(registry& r, entity node) {
    const auto node_props = get_node_props(r, node);
    if (!node_props) {
        return std::unexpected(node_props.error());
    }

    const auto node_type = node_props.value().get().type;

    r.destroy(node);

    const auto& graph_schema = r.ctx().get<schema_graph>();
    for (const auto& relationship_schema : graph_schema.relationships) {
        if (relationship_schema.source.hash != node_type &&
            relationship_schema.target.hash != node_type) {
            continue;
        }

        auto view = view_relationships(r, relationship_schema.type.hash);
        for (auto relationship : view) {
            const auto& relationship_props = view.get<relationship_base>(relationship);
            if (relationship_props.source == node || relationship_props.target == node) {
                r.destroy(relationship);
            }
        }
    }

    return {};
}

expected<void> delete_relationship(registry& r, entity relationship) {
    if (auto relationship_props = get_relationship_props(r, relationship); !relationship_props) {
        return std::unexpected(relationship_props.error());
    }

    r.destroy(relationship);

    return {};
}

} // namespace graph
