# graph :shrug:

Proof of concept for implementing a graph database using [EnTT](https://github.com/skypjack/entt) for storage. The motivation was to have a simple and lightweight implementation, meant for smallish databases.

This implementation includes the following:
 - The graph is made of nodes and relationships.
 - It is a property graph: both nodes and relationships can have properties.
 - All nodes and relationships have a type, which determines what properties they have.
 - The type of a relationship mandates the type of the source and target nodes.
 - The list of available types is determined by a user-supplied schema, which must be loaded up front.
 - A node can have multiple relationships with other nodes (including relationships with itself).
 - A node can have more than one relationship of the same type with the same node (presumably with different properties, but not necessarily).
 - The data is stored in RAM.
 - Functions are available to load a schema, list of nodes, and list of relationships from JSON data.
 - Functions are available to dump all the above to JSON, for backup and persistent storage.
 - Functions are available to query:
   - The type of a node
   - The properties of a node
   - The type of a relationship
   - The source and target of a relationship
   - The properties of a relationship
   - The relationships of a node (all of them, or just the relationships of a given type)
   - The list of all nodes of a given type
   - The list of all relationships of a given type
 - Functions are available to add:
   - A new node
   - A new relationship
 - Functions are available to replace (in full, but type must be preserved):
   - An existing node
   - An existing relationship
 - Functions are available to delete:
   - An existing node (this also deletes all connected relationships)
   - An existing relationship

The public API is in [`graph_core.hpp`](graph-core/include/graph/graph_core.hpp).

Not included:
 - Multi-threading. Not used internally, and the API is not thread-safe.
 - Encryption. The data is stored in plain binary format in RAM.
 - Offloading part of the database to disk to reduce RAM usage. All data is stored in RAM. However, the entire database can be dumped to JSON and saved to disk for backups and persistence.
 - No function is currently available for partial edits of nodes and relationships (only replace, or delete + add). There is nothing fundamental preventing this, just lack of time.
 - There was a plan to implement a REST API on top of this using [Crow](https://github.com/CrowCpp/Crow), but this was not started.
 - There was also a plan to implement a generic query, similar to Cypher, but this is a huge job. Initially I wanted to build something different, that would be simpler (only one-liners) yet making certain basic queries more natural than Cypher (in particular, having a one-liner for "give me nodes of type X that do NOT have a relationship Y with another node").


## Implementation details

Functions that can reasonably be expected to fail for certain inputs have a return type of `expected<T>`, which gives a simple string as  `.error()` on failure. If the return type is not `expected<T>`, then the function is expected to always succeed (baring exceptional circumstances, like running out of resources, in which case exceptions may be thrown).

Nodes and relationships are encoded as entities, and their properties are encoded as components (each property separately, to allow for efficient storage and queries by property). The type of a node or relationship is encoded both in the `node_base`/`relationship_base` component (for fast identification), and as a tag (for fast iteration). The ID of a node or relationship is thus an `entt::entity` value (64 bit integer). In JSON, the IDs are stored as strings, and the functions `id_to_string()`/`id_from_string()` are available to do the conversion.

For best data locality and fast access, the schema is encoded in binary format in a compact data structure. This means there are some compile-time restrictions on:
 - the max number of unique node types (32)
 - the max number of unique relationship types (32)
 - the max number of property per node/relationship (16)
 - the max length of a node/relationship type string (32)

These default values can be changed at configure time with CMake, see [`CMakeLists.txt`](graph-core/CMakeLists.txt).

Note however that this applies only to the schema. The database itself does not have similar restriction, in particular the following is only limited by the available RAM:
 - the number of nodes
 - the number of relationships
 - the number of relationships for a given node

Each property of a given type is encoded in a separate pool. E.g., if we have two types "T1" and "T2" each with properties "P1" and "P2", then "T1/P1", "T1/P2", "T2/P1", "T2/P2" are all stored in separate pools (even if the property shares the same name and type as a property of a different type). Pools are allocated for the data type specified in the schema, with no overhead except for strings. Strings can be stored on the heap, although we store small strings (smaller than 128 characters) in-place in the pool. Better performance could be obtained by adding new string types of fixed length (e.g., `"string64"` for a 64-character-long string), which are not allowed to migrate to the heap if too long.


## Benchmarks

The following was measured on a Ryzen 5 2600 on Linux on 07/05/2023 for commit 57ca37c355409385c5397118b6b25a9953ded271.

An empty node (no properties) consumes about 50 bytes of RAM. A node with properties additionally consumes:
 - 128 bytes per string property
 - 8 bytes per float or integer
 - 1 byte per bool property
 - an overhead of 16-20 bytes per property

Creating 10 million empty nodes takes 2 seconds and consumes 0.5 GB. Creating 10 million non-empty nodes (3 string properties, all strings smaller than 128 chars, plus 2 integer properties) takes 6 seconds and consumes 5.4 GB.
