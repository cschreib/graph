# graph

Proof of concept for implementing a graph database using [EnTT](https://github.com/skypjack/entt) for storage. The motivation was to have a simple and lightweight implementation, meant for smallish databases.

The public API is in [`include/graph/graph.hpp`](include/graph/graph.hpp). Functions that can reasonably be expected to fail for certain inputs have a return type of `expected<T>`, which gives a simple string as  `.error()` on failure. If the return type is not `expected<T>`, then the function is expected to always succeed (baring exceptional circumstances, like running out of resources, in which case exceptions may be thrown).

This implementation includes the following:
 - The graph is made of nodes and relationships.
 - It is a property graph: both nodes and relationships can have properties.
 - All nodes and relationships have a type, which determines what properties they have.
 - The type of a relationship mandates the type of the source and target nodes.
 - The list of available types is determined by a user-supplied schema, which must be loaded up front.
 - The data is stored in RAM.
 - Functions are available to load a schema, list of nodes, and list of relationships from JSON data.
 - Functions are available to dump all the above to JSON, for backup and persistant storage.
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
 - Functions are available to delete:
   - A node (deletes all connected relationships)
   - A relationship
 - No function is currently available to edit nodes and relationships (only through delete and add). There is nothing fundamental preventing this, just lack of time.
 - There was a plan to implement a REST API on top of this using [Crow](https://github.com/CrowCpp/Crow), but this was not started.
 - There was also a plan to implement a generic query, similar to Cypher, but this is a huge job. Initially I wanted to build something different, that would be simpler (only one-liners) yet making certain basic queries more natural than Cypher (in particular, having a one-liner for "give me nodes of type X that do NOT have a relationship Y with another node").

