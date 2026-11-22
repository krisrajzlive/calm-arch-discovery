// Cypher queries over the CALM graph loaded by graph/neo4j_loader.py.
//
// Parameters (the loader's --report flag supplies them; in Neo4j Browser or cypher-shell run
//   :param architecture => 'payments-platform'
//   :param service      => 'orders-api'
// first). Each query starts with a "// @query:" line so the loader can run them one by one.
//
// Graph shape:
//   (:CalmNode:Service|Database|WebClient|Network|System {unique_id, name, owner, ...})
//   (:CalmNode)-[:HAS_CONTROL]->(:Control {control_id, status})
//   (:CalmNode)-[:CONNECTS_TO {protocol, tls, confidence}]->(:CalmNode)
//   (:CalmNode)-[:DEPLOYED_IN]->(:Network)    (:System)-[:COMPOSED_OF]->(:CalmNode)

// @query: 1 services-without-controls
// The same rule the CI gate enforces (pipeline/calm_validator.py): a node with no control at
// all. Empty for a freshly discovered document; non-empty after hand edits.
MATCH (n:CalmNode {architecture: $architecture})
WHERE n.node_type IN ['service', 'database', 'webclient']
  AND NOT (n)-[:HAS_CONTROL]->(:Control)
RETURN n.name AS node, n.node_type AS type, n.owner AS owner
ORDER BY node;

// @query: 1b nodes-with-unverified-controls
// Controls the policy requires but the repository gives no evidence for (the review backlog).
MATCH (n:CalmNode {architecture: $architecture})-[:HAS_CONTROL]->(c:Control {status: 'unverified'})
RETURN n.name AS node, n.owner AS owner, collect(c.control_id) AS unverified_controls
ORDER BY size(unverified_controls) DESC, node;

// @query: 2 transitive-dependencies
// Everything $service depends on, directly or indirectly, with the shortest hop count.
// Cypher never reuses a relationship inside one path, so cycles cannot loop forever; the
// upper bound keeps the search cheap on large graphs. `d <> s` drops the start node, which a
// cycle would otherwise report as its own dependency.
MATCH path = (s:CalmNode {architecture: $architecture, unique_id: $service})
             -[:CONNECTS_TO*1..10]->(d:CalmNode)
WHERE d <> s
RETURN d.name AS dependency, d.node_type AS type, min(length(path)) AS hops
ORDER BY hops, dependency;

// @query: 3 circular-dependency-chains
// Simple cycles in the runtime call graph. Anchoring on the cycle member with the smallest
// id reports each cycle once instead of once per rotation.
MATCH path = (a:CalmNode {architecture: $architecture})-[:CONNECTS_TO*1..8]->(a)
WHERE ALL(n IN nodes(path) WHERE a.unique_id <= n.unique_id)
  AND ALL(n IN nodes(path)[1..-1] WHERE single(m IN nodes(path)[1..-1] WHERE m = n))
RETURN [n IN nodes(path) | n.unique_id] AS cycle, length(path) AS length
ORDER BY length, cycle;

// @query: 4 unencrypted-relationships
// Connections not evidenced as encrypted. CALM's protocol enum has no gRPC, so gRPC is modelled
// as HTTP/HTTPS/mTLS plus application_protocol = 'gRPC' and is judged on its transport.
// `tls` carries evidence the enum cannot (e.g. JDBC with sslmode=require, mesh mTLS).
MATCH (a:CalmNode {architecture: $architecture})-[r:CONNECTS_TO]->(b:CalmNode)
WHERE NOT r.protocol IN ['HTTPS', 'mTLS', 'TLS', 'SFTP']
  AND coalesce(r.tls, false) = false
RETURN a.name AS source, b.name AS target, r.protocol AS protocol,
       coalesce(r.application_protocol, '-') AS application_protocol,
       r.confidence AS confidence
ORDER BY source, target;

// @query: 5 internet-to-datastore-paths
// Attack-surface view: every call path from a public ingress to a database, and whether each
// hop on it is encrypted. Routes are simple paths: a node is never revisited.
MATCH path = (e:CalmNode {architecture: $architecture, role: 'ingress'})
             -[:CONNECTS_TO*1..6]->(d:CalmNode {node_type: 'database'})
WHERE ALL(n IN nodes(path) WHERE single(m IN nodes(path) WHERE m = n))
RETURN [n IN nodes(path) | n.name] AS route,
       ALL(r IN relationships(path) WHERE r.tls) AS fully_encrypted
ORDER BY length(path), route;
