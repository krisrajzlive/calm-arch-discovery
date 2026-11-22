"""Static lookup tables the scanner uses to classify images, libraries and URL schemes."""

from __future__ import annotations

import re

# image path segment -> technology
IMAGE_TECH: dict[str, str] = {
    "postgres": "postgres",
    "postgresql": "postgres",
    "timescaledb": "postgres",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "redis": "redis",
    "valkey": "valkey",
    "memcached": "memcached",
    "cassandra": "cassandra",
    "mssql": "sqlserver",
    "cockroach": "cockroachdb",
    "neo4j": "neo4j",
    "elasticsearch": "elasticsearch",
    "opensearch": "opensearch",
    "rabbitmq": "rabbitmq",
    "kafka": "kafka",
    "mailhog": "mailhog",
    "nginx": "nginx",
    "tinkerpop": "gremlin-server",
    "gremlin-server": "gremlin-server",
}

# technologies that are data stores -> CALM `database` node
DATASTORE_TECH = {
    "postgres",
    "mysql",
    "mariadb",
    "mongodb",
    "redis",
    "valkey",
    "memcached",
    "cassandra",
    "sqlserver",
    "cockroachdb",
    "neo4j",
    "elasticsearch",
    "opensearch",
}

# default wire protocol (CALM enum) when a dependency is declared without a URL scheme
TECH_PROTOCOL: dict[str, str] = {
    "postgres": "JDBC",
    "mysql": "JDBC",
    "mariadb": "JDBC",
    "sqlserver": "JDBC",
    "cockroachdb": "JDBC",
    "redis": "TCP",
    "valkey": "TCP",
    "memcached": "TCP",
    "mongodb": "TCP",
    "cassandra": "TCP",
    "neo4j": "TCP",
    "kafka": "TCP",
    "rabbitmq": "AMQP",
    "mailhog": "TCP",
    "elasticsearch": "HTTP",
    "opensearch": "HTTP",
    "gremlin-server": "WebSocket",
}

# client library -> technology it talks to
PY_CLIENT_LIBS: dict[str, str] = {
    "psycopg": "postgres",
    "psycopg2": "postgres",
    "psycopg2-binary": "postgres",
    "asyncpg": "postgres",
    "pg8000": "postgres",
    "pymysql": "mysql",
    "mysqlclient": "mysql",
    "mysql-connector-python": "mysql",
    "aiomysql": "mysql",
    "redis": "redis",
    "aioredis": "redis",
    "pymongo": "mongodb",
    "motor": "mongodb",
    "pika": "rabbitmq",
    "aio-pika": "rabbitmq",
    "kombu": "rabbitmq",
    "confluent-kafka": "kafka",
    "kafka-python": "kafka",
    "aiokafka": "kafka",
    "neo4j": "neo4j",
    "elasticsearch": "elasticsearch",
    "opensearch-py": "opensearch",
}
NPM_CLIENT_LIBS: dict[str, str] = {
    "pg": "postgres",
    "pg-promise": "postgres",
    "mysql": "mysql",
    "mysql2": "mysql",
    "redis": "redis",
    "ioredis": "redis",
    "mongodb": "mongodb",
    "mongoose": "mongodb",
    "amqplib": "rabbitmq",
    "kafkajs": "kafka",
    "neo4j-driver": "neo4j",
    "@elastic/elasticsearch": "elasticsearch",
}

NPM_FRONTEND = {"react", "react-dom", "vue", "@angular/core", "svelte", "solid-js", "preact"}
NPM_BACKEND = {
    "express",
    "fastify",
    "koa",
    "@nestjs/core",
    "@hapi/hapi",
    "hapi",
    "next",
    "nuxt",
    "restify",
}

# URL scheme -> (CALM protocol, TLS by default, application protocol)
SCHEMES: dict[str, tuple[str, bool, str | None]] = {
    "http": ("HTTP", False, None),
    "https": ("HTTPS", True, None),
    "ws": ("WebSocket", False, None),
    "wss": ("WebSocket", True, None),
    "grpc": ("HTTP", False, "gRPC"),
    "grpcs": ("HTTPS", True, "gRPC"),
    "postgres": ("JDBC", False, "postgresql"),
    "postgresql": ("JDBC", False, "postgresql"),
    "mysql": ("JDBC", False, "mysql"),
    "mariadb": ("JDBC", False, "mariadb"),
    "sqlserver": ("JDBC", False, "sqlserver"),
    "mssql": ("JDBC", False, "sqlserver"),
    "mongodb": ("TCP", False, "mongodb"),
    "mongodb+srv": ("TCP", True, "mongodb"),
    "redis": ("TCP", False, "redis"),
    "rediss": ("TLS", True, "redis"),
    "amqp": ("AMQP", False, None),
    "amqps": ("AMQP", True, None),
    "smtp": ("TCP", False, "smtp"),
    "smtps": ("TLS", True, "smtp"),
    "ldap": ("LDAP", False, None),
    "ldaps": ("LDAP", True, None),
    "ftp": ("FTP", False, None),
    "sftp": ("SFTP", True, None),
    "tcp": ("TCP", False, None),
    "tls": ("TLS", True, None),
    "kafka": ("TCP", False, "kafka"),
    "bolt": ("TCP", False, "bolt"),
    "neo4j": ("TCP", False, "bolt"),
    "bolt+s": ("TCP", True, "bolt"),
    "neo4j+s": ("TCP", True, "bolt"),
}

# connection-string options that turn TLS on for schemes that are plaintext by default
TLS_QUERY = re.compile(
    r"(sslmode=(require|verify-ca|verify-full)|ssl(-mode)?=(true|required|verify[_-]\w+|1)"
    r"|tls=true|usessl=true|encrypt=true)",
    re.IGNORECASE,
)

AUTH_ENV = re.compile(r"(OIDC|JWT|JWKS|OAUTH|AUTH0|SAML|KEYCLOAK|ISSUER)", re.IGNORECASE)
HOST_ENV = re.compile(r"(^|_)(HOST|HOSTNAME|ADDR|ADDRESS|SERVER)$", re.IGNORECASE)
OWNER_LABELS = ("owner", "team", "app.kubernetes.io/owner")
ENVIRONMENT_LABELS = ("environment", "env", "app.kubernetes.io/environment")
