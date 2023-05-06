#include "graph/graph.hpp"

#include <snitch/snitch.hpp>

using namespace nlohmann::literals;
using namespace std::literals;

namespace snitch {
bool append(small_string_span ss, const nlohmann::json& j) noexcept {
    return append(ss, j.dump());
}
} // namespace snitch

#define REQUIRE_VALID(RET)                                                                         \
    do {                                                                                           \
        if (!(RET).has_value()) {                                                                  \
            FAIL_CHECK((RET).error());                                                             \
            FAIL(#RET " was not valid");                                                           \
        }                                                                                          \
    } while (0)

namespace {
// clang-format off
    const nlohmann::json test_schema =
R"({
    "nodes": {
        "customer": {
            "properties": {
                "id": "string",
                "name": "string"
            }
        },
        "requirement": {
            "properties": {
                "id": "string",
                "title": "string",
                "description": "string"
            }
        },
        "risk": {
            "properties": {
                "id": "string",
                "title": "string",
                "description": "string",
                "probability": "integer",
                "severity": "integer"
            }
        }
    },
    "relationships": {
        "mitigates": {
            "source": "requirement",
            "target": "risk"
        },
        "introduces": {
            "source": "requirement",
            "target": "risk"
        },
        "needs": {
            "source": "customer",
            "target": "requirement",
            "properties": {
                "priority": "string"
            }
        }
    }
})"_json;
// clang-format on
} // namespace

TEST_CASE("schema load/save good") {
    const nlohmann::json data_in = test_schema;

    entt::registry r;
    graph::load_schema(r, data_in);

    const nlohmann::json data_out = graph::save_schema(r);

    CHECK(data_in == data_out);
}

TEST_CASE("node load bad") {
    entt::registry r;
    graph::load_schema(r, test_schema);

    SECTION("missing type") {
        auto e = graph::add_node(r, R"({})"_json);
        REQUIRE(!e.has_value());
        CHECK(e.error() == "missing node type");
    }

    SECTION("unknown type") {
        auto e = graph::add_node(r, R"({"type": "bazooka"})"_json);
        REQUIRE(!e.has_value());
        CHECK(e.error() == "unknown node type");
    }

    SECTION("empty property") {
        auto e = graph::add_node(r, R"({"type": "requirement"})"_json);
        REQUIRE(!e.has_value());
        CHECK(e.error() == "missing property");
    }

    SECTION("missing property") {
        auto e = graph::add_node(r, R"({"type": "requirement", "properties": {"id": "R1"}})"_json);
        REQUIRE(!e.has_value());
        CHECK(e.error() == "missing property");
    }

    // This cannot be triggered with nlohmann::json.
#if 0
    SECTION("duplicate property") {
        auto e = graph::add_node(
            r,
            R"({"type": "requirement", "properties": {"id": "R1", "id": "R2", "title": "abc", "description": "def"}})"_json);
        REQUIRE(!e.has_value());
        CHECK(e.error() == "duplicate property");
    }
#endif

    SECTION("unknown property") {
        auto e = graph::add_node(
            r,
            R"({"type": "requirement", "properties": {"id": "R1", "title": "abc", "description": "def", "kitten": false}})"_json);
        REQUIRE(!e.has_value());
        CHECK(e.error() == "unknown property");
    }

    SECTION("wrong type property") {
        auto e = graph::add_node(
            r,
            R"({"type": "requirement", "properties": {"id": "R1", "title": "abc", "description": 0}})"_json);
        REQUIRE(!e.has_value());
        CHECK(e.error() == "expected string value");
    }
}

TEST_CASE("node load good") {
    entt::registry r;
    graph::load_schema(r, test_schema);

    const auto node_ret = graph::add_node(r, R"({
        "type": "requirement",
        "properties": {
            "id": "R1",
            "title": "Nodes checked against schema",
            "description": "Nodes in the database are checked against a schema, to ensure integrity. Nodes that do not conform to the schema cannot be added to the database."
        }
    })"_json);

    REQUIRE_VALID(node_ret);
    const auto node = node_ret.value();

    {
        auto p = graph::get_node_property(r, node, "id"sv);
        REQUIRE_VALID(p);
        CHECK(p.value().get<std::string>() == "R1"sv);
    }
    {
        auto p = graph::get_node_property(r, node, "title"sv);
        REQUIRE_VALID(p);
        CHECK(p.value().get<std::string>() == "Nodes checked against schema"sv);
    }
    {
        auto p = graph::get_node_property(r, node, "description"sv);
        REQUIRE_VALID(p);
        CHECK(
            p.value().get<std::string>() ==
            "Nodes in the database are checked against a schema, to ensure integrity. Nodes that do not conform to the schema cannot be added to the database."sv);
    }
}
