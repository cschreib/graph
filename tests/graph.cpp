#include "graph/graph.hpp"

#include <snitch/snitch.hpp>

using namespace nlohmann::literals;

namespace snitch {
bool append(small_string_span ss, const nlohmann::json& j) noexcept {
    return append(ss, j.dump());
}
} // namespace snitch

TEST_CASE("schema load/save") {
    // clang-format off
    const nlohmann::json data_in =
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
    "links": {
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

    entt::registry r;
    graph::load_schema(r, data_in);
    nlohmann::json data_out = graph::save_schema(r);

    CHECK(data_in == data_out);
}
