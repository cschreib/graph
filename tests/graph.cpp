#include "graph/graph.hpp"

#include <snitch/snitch.hpp>

using namespace nlohmann::literals;
using namespace std::literals;

namespace snitch {
bool append(small_string_span ss, const nlohmann::json& j) noexcept {
    return append(ss, j.dump());
}
} // namespace snitch

#define REQUIRE_INVALID(RET, ERROR)                                                                \
    do {                                                                                           \
        if ((RET).has_value()) {                                                                   \
            FAIL(#RET " was valid");                                                               \
        } else {                                                                                   \
            CHECK((RET).error() == (ERROR));                                                       \
        }                                                                                          \
    } while (0)

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

const nlohmann::json test_node_requirement =
R"({
    "type": "requirement",
    "properties": {
        "id": "Req.1",
        "title": "Nodes checked against schema",
        "description": "Nodes in the database are checked against a schema, to ensure integrity. Nodes that do not conform to the schema cannot be added to the database."
    }
})"_json;

const nlohmann::json test_node_risk =
R"({
    "type": "risk",
    "properties": {
        "id": "Ri.1",
        "title": "Data in node is incorrectly entered",
        "description": "User inputs data into the database that is unexpected, or is missing critical data.",
        "probability": 5,
        "severity": 5
    }
})"_json;

const nlohmann::json test_node_customer =
R"({
    "type": "customer",
    "properties": {
        "id": "super_corp",
        "name": "Super Corp Ltd."
    }
})"_json;

const nlohmann::json test_relationship_mitigates =
R"({
    "type": "mitigates",
    "source": 0,
    "target": 1
})"_json;

const nlohmann::json test_relationship_needs =
R"({
    "type": "needs",
    "source": 2,
    "target": 0,
    "properties": {
        "priority": "MUST"
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

TEST_CASE("add_node good") {
    entt::registry r;
    graph::load_schema(r, test_schema);

    const auto node_ret = graph::add_node(r, test_node_requirement);
    REQUIRE_VALID(node_ret);
    const auto node = node_ret.value();

    {
        auto p = graph::get_node_property(r, node, "id"sv);
        REQUIRE_VALID(p);
        CHECK(p.value().get<std::string>() == "Req.1"sv);
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
    {
        auto p = graph::get_node_properties(r, node);
        REQUIRE_VALID(p);
        CHECK(p.value() == R"({
            "id": "Req.1",
            "title": "Nodes checked against schema",
            "description": "Nodes in the database are checked against a schema, to ensure integrity. Nodes that do not conform to the schema cannot be added to the database."
        })"_json);
    }
}

TEST_CASE("add_node bad") {
    entt::registry r;
    graph::load_schema(r, test_schema);

    SECTION("missing type") {
        auto e = graph::add_node(r, R"({})"_json);
        REQUIRE_INVALID(e, "missing node type");
    }

    SECTION("unknown type") {
        auto e = graph::add_node(r, R"({"type": "bazooka"})"_json);
        REQUIRE_INVALID(e, "unknown node type");
    }

    SECTION("empty property") {
        auto e = graph::add_node(r, R"({"type": "requirement"})"_json);
        REQUIRE_INVALID(e, "missing property");
    }

    SECTION("missing property") {
        auto e = graph::add_node(r, R"({"type": "requirement", "properties": {"id": "R1"}})"_json);
        REQUIRE_INVALID(e, "missing property");
    }

    // This cannot be triggered with nlohmann::json.
#if 0
    SECTION("duplicate property") {
        auto e = graph::add_node(
            r,
            R"({"type": "requirement", "properties": {"id": "R1", "id": "R2", "title": "abc", "description": "def"}})"_json);
        REQUIRE_INVALID(e, "duplicate property");
    }
#endif

    SECTION("unknown property") {
        auto e = graph::add_node(
            r,
            R"({"type": "requirement", "properties": {"id": "R1", "title": "abc", "description": "def", "kitten": false}})"_json);
        REQUIRE_INVALID(e, "unknown property");
    }

    SECTION("wrong type property") {
        auto e = graph::add_node(
            r,
            R"({"type": "requirement", "properties": {"id": "R1", "title": "abc", "description": 0}})"_json);
        REQUIRE_INVALID(e, "expected string value");
    }
}

namespace {
void add_test_nodes(entt::registry& r) {
    auto n1 = graph::add_node(r, test_node_requirement);
    REQUIRE_VALID(n1);
    REQUIRE(static_cast<std::uint64_t>(n1.value()) == 0);
    auto n2 = graph::add_node(r, test_node_risk);
    REQUIRE_VALID(n2);
    REQUIRE(static_cast<std::uint64_t>(n2.value()) == 1);
    auto n3 = graph::add_node(r, test_node_customer);
    REQUIRE_VALID(n3);
    REQUIRE(static_cast<std::uint64_t>(n3.value()) == 2);
}
} // namespace

TEST_CASE("add_relationship good") {
    entt::registry r;
    graph::load_schema(r, test_schema);
    add_test_nodes(r);

    SECTION("no properties") {
        const auto relationship_ret = graph::add_relationship(r, test_relationship_mitigates);
        REQUIRE_VALID(relationship_ret);
    }

    SECTION("duplicate") {
        const auto r1 = graph::add_relationship(r, test_relationship_mitigates);
        REQUIRE_VALID(r1);
        const auto r2 = graph::add_relationship(r, test_relationship_mitigates);
        REQUIRE_VALID(r2);
        CHECK(r1.value() != r2.value());
        CHECK(r.valid(r1.value()));
        CHECK(r.valid(r2.value()));
    }

    SECTION("with properties") {
        const auto relationship_ret = graph::add_relationship(r, test_relationship_needs);
        REQUIRE_VALID(relationship_ret);
        const auto relationship = relationship_ret.value();

        {
            auto p = graph::get_relationship_property(r, relationship, "priority"sv);
            REQUIRE_VALID(p);
            CHECK(p.value().get<std::string>() == "MUST"sv);
        }
        {
            auto p = graph::get_relationship_properties(r, relationship);
            REQUIRE_VALID(p);
            CHECK(p.value() == R"({
                "priority": "MUST"
            })"_json);
        }
    }
}

TEST_CASE("add_relationship bad") {
    entt::registry r;
    graph::load_schema(r, test_schema);
    add_test_nodes(r);

    SECTION("missing type") {
        auto e = graph::add_relationship(r, R"({})"_json);
        REQUIRE_INVALID(e, "missing relationship type");
    }

    SECTION("unknown type") {
        auto e =
            graph::add_relationship(r, R"({"type": "bazooka", "source": 2, "target": 0})"_json);
        REQUIRE_INVALID(e, "unknown relationship type");
    }

    SECTION("missing source") {
        auto e = graph::add_relationship(r, R"({"type": "mitigates", "target": 1})"_json);
        REQUIRE_INVALID(e, "missing relationship source");
    }

    SECTION("missing target") {
        auto e = graph::add_relationship(r, R"({"type": "mitigates", "source": 0})"_json);
        REQUIRE_INVALID(e, "missing relationship target");
    }

    SECTION("empty property") {
        auto e = graph::add_relationship(r, R"({"type": "needs", "source": 2, "target": 0})"_json);
        REQUIRE_INVALID(e, "missing property");
    }

    SECTION("missing property") {
        auto e = graph::add_relationship(
            r, R"({"type": "needs", "source": 2, "target": 0, "properties": {}})"_json);
        REQUIRE_INVALID(e, "missing property");
    }

    // This cannot be triggered with nlohmann::json.
#if 0
    SECTION("duplicate property") {
        auto e = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 2, "target": 0, "properties": {"priority": "MUST", "priority": "SHOULD"}})"_json);
        REQUIRE_INVALID(e, "duplicate property");
    }
#endif

    SECTION("unknown property") {
        auto e = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 2, "target": 0, "properties": {"priority": "MUST", "kitten": false}})"_json);
        REQUIRE_INVALID(e, "unknown property");
    }

    SECTION("wrong type property") {
        auto e = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 2, "target": 0, "properties": {"priority": 1}})"_json);
        REQUIRE_INVALID(e, "expected string value");
    }

    SECTION("source does not exist") {
        auto e = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 100, "target": 0, "properties": {"priority": "MUST"}})"_json);
        REQUIRE_INVALID(e, "source does not exist");
    }

    SECTION("source is not a node") {
        auto e1 = graph::add_relationship(r, test_relationship_mitigates);
        REQUIRE_VALID(e1);
        REQUIRE(static_cast<std::uint64_t>(e1.value()) == 3);

        auto e2 = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 3, "target": 0, "properties": {"priority": "MUST"}})"_json);
        REQUIRE_INVALID(e2, "source is not a node");
    }

    SECTION("wrong source type") {
        auto e = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 1, "target": 0, "properties": {"priority": "MUST"}})"_json);
        REQUIRE_INVALID(e, "source has incorrect type");
    }

    SECTION("target does not exist") {
        auto e = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 2, "target": 100, "properties": {"priority": "MUST"}})"_json);
        REQUIRE_INVALID(e, "target does not exist");
    }

    SECTION("target is not a node") {
        auto e1 = graph::add_relationship(r, test_relationship_mitigates);
        REQUIRE_VALID(e1);
        REQUIRE(static_cast<std::uint64_t>(e1.value()) == 3);

        auto e2 = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 2, "target": 3, "properties": {"priority": "MUST"}})"_json);
        REQUIRE_INVALID(e2, "target is not a node");
    }

    SECTION("wrong target type") {
        auto e = graph::add_relationship(
            r,
            R"({"type": "needs", "source": 2, "target": 1, "properties": {"priority": "MUST"}})"_json);
        REQUIRE_INVALID(e, "target has incorrect type");
    }
}
