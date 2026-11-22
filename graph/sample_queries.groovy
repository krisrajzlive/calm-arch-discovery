// Gremlin equivalents of graph/sample_queries.cypher, for Amazon Neptune / TinkerPop.
// One traversal per line (no variables) so each can be submitted on its own.
// Replace 'payments-platform' / 'orders-api' with your architecture and service.
//
// Model: vertices carry their node type as label (Service, Database, WebClient, Network,
// System, Control); edges are CONNECTS_TO, DEPLOYED_IN, COMPOSED_OF, HAS_CONTROL.

// 1. services-without-controls                       (Cypher: NOT (n)-[:HAS_CONTROL]->())
g.V().has('architecture', 'payments-platform').hasLabel('Service', 'Database', 'WebClient').not(__.out('HAS_CONTROL')).values('name')

// 1b. nodes-with-unverified-controls                 (Cypher: collect(c.control_id) ... GROUP BY node)
g.V().has('architecture', 'payments-platform').hasLabel('Control').has('status', 'unverified').group().by(__.in('HAS_CONTROL').values('name')).by(__.values('control_id').fold())

// 2. transitive-dependencies                         (Cypher: -[:CONNECTS_TO*1..10]->)
//    simplePath() is the cycle guard that Cypher gives you through relationship uniqueness.
g.V('payments-platform/orders-api').repeat(__.out('CONNECTS_TO').simplePath()).times(10).emit().dedup().values('name')

// 3. circular-dependency-chains                      (Cypher: MATCH (a)-[:CONNECTS_TO*1..8]->(a))
//    walk simple paths out of every vertex, keep those whose next hop returns to the start,
//    then dedup() on the sorted set of members so each cycle is reported once, not once per rotation.
g.V().has('architecture', 'payments-platform').hasLabel('Service', 'Database', 'WebClient').as('a').repeat(__.out('CONNECTS_TO').simplePath()).times(8).emit().out('CONNECTS_TO').where(eq('a')).path().by('unique_id').dedup().by(__.unfold().dedup().order().fold())

// 4. unencrypted-relationships                       (Cypher: NOT r.protocol IN [...] AND tls = false)
g.E().hasLabel('CONNECTS_TO').has('architecture', 'payments-platform').not(__.has('protocol', within('HTTPS', 'mTLS', 'TLS', 'SFTP'))).has('tls', false).project('source', 'target', 'protocol').by(__.outV().values('name')).by(__.inV().values('name')).by('protocol')

// 5. internet-to-datastore-paths                     (Cypher: ingress -[:CONNECTS_TO*1..6]-> database)
g.V().has('architecture', 'payments-platform').has('role', 'ingress').repeat(__.out('CONNECTS_TO').simplePath()).times(6).emit(__.hasLabel('Database')).path().by('name')
