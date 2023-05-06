# graph

Proof of concept for implementing a graph database using [EnTT](https://github.com/skypjack/entt) for storage. The motivation was to have a simple and lightweight implementation, meant for smallish databases.

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
 - Functions are available to add:
   - A new node
   - A new relationship
 - No function is currently available to edit nodes and relationships (only through delete and add). There is nothing fundamental preventing this, just lack of time.
 - There was a plan to implement a REST API on top of this using [Crow](https://github.com/CrowCpp/Crow), but this was not started.

The public API is in [`include/graph/graph.hpp`](include/graph/graph.hpp).
