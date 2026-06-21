# %% [markdown]
# # Agent 2 — Asset Criticality Agent
# 
# **Receives:** `working.csv` from Agent 1 (already has `asset_id` for all rows, and pre-filled criticality columns for assets that existed in DB).
# 
# **Does:**
# 1. Reads CSV, finds unique assets that are missing criticality data (new assets)
# 2. For each new asset, runs the full inference pipeline as functions (role → exposure → environment → cloud → dependency → criticality)
# 3. If role and environment and exposure and cloud are all UNKNOWN after deterministic inference, calls gemini-2.5-flash to fill the gap (LLM fallback)
# 4. Writes all computed fields back into CSV
# 5. Batch upserts the full asset context into the DB
# 
# All inference logic lives as functions in this one notebook — no separate files needed.

# %%
# ── Imports ───────────────────────────────────────────────────────────────
import os, json, logging, ipaddress, time
from datetime import datetime, timezone
from typing import TypedDict, Optional
import re
from urllib.parse import urlparse
import pandas as pd
import psycopg2, psycopg2.extras
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

from langgraph.graph import StateGraph, END
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("asset_criticality")


# %%
# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — ALL HARDCODED MAPPINGS (enriched for production coverage)
#
# These are the single source of truth. Enriched well beyond the originals
# so real scanner output (Rapid7, Qualys, Tenable, Wiz, Prisma, AWS Inspector)
# rarely hits UNKNOWN.
# ═══════════════════════════════════════════════════════════════════════════

# ── Port → Role mapping ───────────────────────────────────────────────────
# Added: InfluxDB (8086), Neo4j (7474/7687),
#        ScyllaDB (9042 shared w/ Cassandra), Vault (8200), etcd (2379/2380),
#        Consul (8500/8600), Kubernetes API (6443), Prometheus (9090),
#        Alertmanager (9093), Grafana (3000), Elasticsearch (9200/9300),
#        Kibana (5601), OpenSearch (9200/9300), Logstash (5044),
#        GitLab (8929), Harbor (443 shared), Artifactory (8081)
ROLE_PORT_MAP = {
    "DATABASE": [
        3306,   # MySQL / MariaDB
        5432,   # PostgreSQL
        1521,   # Oracle
        1433,   # MSSQL
        27017,  # MongoDB
        27018,  # MongoDB shard
        6379,   # Redis
        6380,   # Redis TLS
        9042,   # Cassandra / ScyllaDB
        5984,   # CouchDB
        9440,   # ClickHouse HTTPS
        8086,   # InfluxDB
        7474,   # Neo4j HTTP
        7687,   # Neo4j Bolt
        5433,   # Postgres alt
        3307,   # MySQL alt
        1434,   # MSSQL browser
        28017,  # MongoDB web
        11211,  # Memcached
    ],
    "AUTH": [
        389,    # LDAP
        636,    # LDAPS
        88,     # Kerberos
        1812,   # RADIUS auth
        1813,   # RADIUS accounting
        8200,   # HashiCorp Vault
        8201,   # Vault cluster
        8443,   # Keycloak HTTPS (shared)
        4444,   # Keycloak mgmt
        7070,   # Keycloak HTTP alt
    ],
    "WEB": [
        80,     # HTTP
        443,    # HTTPS
        8080,   # HTTP alt
        8443,   # HTTPS alt
        8000,   # common dev HTTP
        8888,   # Jupyter / misc
        3000,   # Grafana / Node dev
        4200,   # Angular dev
        5000,   # Flask / React dev
        5601,   # Kibana
    ],
    "MANAGEMENT": [
        22,     # SSH
        3389,   # RDP
        5900,   # VNC
        5901,   # VNC display 1
        5985,   # WinRM HTTP
        5986,   # WinRM HTTPS
        623,    # IPMI / BMC
        664,    # IPMI alt
        2222,   # SSH alt
        6443,   # Kubernetes API
        2379,   # etcd client
        2380,   # etcd peer
        8500,   # Consul HTTP
        8501,   # Consul HTTPS
        10250,  # Kubelet API
        10255,  # Kubelet read-only
    ],
    "MAIL": [
        25,     # SMTP
        465,    # SMTPS
        587,    # SMTP submission
        110,    # POP3
        995,    # POP3S
        143,    # IMAP
        993,    # IMAPS
        2525,   # SMTP alt
    ],
    "MESSAGE_BUS": [
        5672,   # RabbitMQ AMQP
        5671,   # RabbitMQ AMQPS
        15672,  # RabbitMQ management
        15671,  # RabbitMQ mgmt HTTPS
        9092,   # Kafka
        9093,   # Kafka SSL
        9094,   # Kafka SASL
        61616,  # ActiveMQ
        61617,  # ActiveMQ SSL
        4369,   # RabbitMQ epmd
        2181,   # ZooKeeper
        2888,   # ZooKeeper follower
        3888,   # ZooKeeper election
    ],
    "MONITORING": [
        9090,   # Prometheus
        9091,   # Prometheus pushgateway
        9093,   # Alertmanager
        9100,   # Node exporter
        3000,   # Grafana (overlaps WEB — component wins)
        8125,   # StatsD
        4317,   # OTLP gRPC
        4318,   # OTLP HTTP
        14268,  # Jaeger HTTP
        16686,  # Jaeger UI
        9411,   # Zipkin
    ],
    "CICD": [
        8080,   # Jenkins (overlaps WEB — component wins)
        50000,  # Jenkins agent
        8929,   # GitLab SSH
        8081,   # Artifactory / Nexus
        8082,   # Nexus Docker repo
    ],
    "STORAGE": [
        2049,   # NFS
        445,    # SMB / Samba
        139,    # NetBIOS
        111,    # portmapper / rpcbind
        9001,   # MinIO console
    ],
}


# ── Component keyword → Role mapping ──────────────────────────────────────
# Enriched: cloud-native names, vendor products, alternate spellings,
# container orchestration, service mesh, secrets management, etc.
ROLE_COMPONENT_MAP = {
    "DATABASE": [
        # Relational
        "mysql", "mariadb", "percona", "aurora",
        "postgres", "postgresql", "timescaledb",
        "oracle", "mssql", "sqlserver", "sql server",
        "sqlite", "cockroachdb", "cockroach",
        # Document
        "mongodb", "mongo", "documentdb", "cosmosdb",
        "couchdb", "couchbase", "firestore",
        # Cache / KV
        "redis", "valkey", "dragonfly", "memcached",
        "dynamodb", "bigtable", "spanner",
        # Column / Analytics
        "cassandra", "scylladb", "scylla",
        "clickhouse", "redshift", "bigquery",
        "snowflake", "databricks", "hive", "hbase",
        # Search
        "elasticsearch", "opensearch", "solr",
        # Graph
        "neo4j", "neptune",
        # Time-series
        "influxdb", "influx", "victoriametrics",
        "prometheus",  # doubles as TSDB
    ],
    "AUTH": [
        # Protocols
        "ldap", "ldaps", "kerberos", "radius", "saml", "oidc",
        # Products
        "active directory", "activedirectory",
        "ad", "adfs", "aad", "azure ad", "entra",
        "okta", "onelogin", "ping", "pingidentity",
        "auth0", "cognito", "firebase auth",
        "keycloak", "freeipa", "gluu", "wso2",
        # Keywords
        "auth", "iam", "sso", "oauth", "jwt",
        "identity", "idp", "mfa", "2fa",
        # Secrets
        "vault", "hashicorp vault", "cyberark",
        "secrets manager", "secretsmanager",
    ],
    "WEB": [
        "nginx", "openresty", "apache", "httpd",
        "iis", "lighttpd", "caddy", "haproxy",
        "traefik", "envoy", "istio",
        "frontend", "react", "angular", "vue",
        "next.js", "nextjs", "nuxt", "svelte",
        "webserver", "web server", "static site",
        "cloudfront", "cdn",
    ],
    "API": [
        "api", "rest", "graphql", "grpc", "rpc",
        "backend", "gateway", "apigw", "kong",
        "springboot", "spring boot", "spring",
        "tomcat", "jetty", "wildfly", "jboss",
        "gunicorn", "uvicorn", "hypercorn", "daphne",
        "node", "nodejs", "express", "fastify", "koa",
        "django", "flask", "fastapi", "aiohttp", "starlette",
        "rails", "sinatra", "rack",
        "laravel", "symfony", "codeigniter",
        "dotnet", ".net", "asp.net", "aspnetcore",
        "microservice", "service", "svc",
    ],
    "MANAGEMENT": [
        "ssh", "sshd", "openssh",
        "rdp", "mstsc", "winrm", "psexec",
        "ansible", "salt", "saltstack",
        "puppet", "chef", "cfengine",
        "terraform", "pulumi", "cloudformation",
        "jumpbox", "jump server", "bastion", "bastion host",
        "pam", "privileged access",
        "kubectl", "kubernetes", "k8s",
        "helm", "rancher", "openshift",
        "aws ssm", "ssm agent", "systems manager",
        "ipmi", "bmc", "idrac", "ilo",
        "etcd", "consul",
    ],
    "MAIL": [
        "smtp", "smtps", "imap", "imaps", "pop3",
        "exchange", "exchange server",
        "postfix", "sendmail", "exim", "qmail",
        "office365", "o365", "microsoft 365",
        "gmail", "google workspace",
        "mail", "mailserver", "mail server", "mta",
        "ses", "sendgrid", "mailgun",
    ],
    "STORAGE": [
        "s3", "minio", "ceph", "rook",
        "nfs", "efs", "fsx",
        "smb", "samba", "cifs",
        "azure blob", "blob storage",
        "gcs", "google cloud storage",
        "gluster", "glusterfs",
        "longhorn", "portworx", "openebs",
        "backup", "veeam", "commvault", "netbackup",
        "storage",
    ],
    "MESSAGE_BUS": [
        "rabbitmq", "rabbit",
        "kafka", "confluent",
        "activemq", "artemis",
        "nats", "nats.io",
        "pulsar", "apache pulsar",
        "nsq", "zeromq", "zmq",
        "aws sqs", "sqs", "sns",
        "azure service bus", "eventhub", "event hub",
        "google pubsub", "pub/sub",
        "mq", "message queue", "message broker",
        "zookeeper", "redpanda",
    ],
    "MONITORING": [
        "prometheus", "alertmanager", "thanos", "cortex", "mimir",
        "grafana", "loki", "tempo",
        "zabbix", "nagios", "icinga", "check_mk",
        "datadog", "newrelic", "dynatrace",
        "splunk", "elastic apm", "apm",
        "cloudwatch", "azure monitor", "stackdriver",
        "pagerduty", "opsgenie",
        "jaeger", "zipkin", "opentelemetry", "otel",
        "fluentd", "fluent bit", "logstash", "filebeat",
        "siem", "wazuh", "ossec",
    ],
    "CICD": [
        "jenkins", "jenkinsx",
        "gitlab", "gitlab-runner", "gitlab runner",
        "github actions", "github runner",
        "argo", "argocd", "argo cd", "argo workflows",
        "tekton", "spinnaker", "teamcity",
        "circleci", "travis", "drone", "concourse",
        "sonarqube", "sonar",
        "nexus", "artifactory", "harbor", "jfrog",
        "build", "deploy", "release", "pipeline",
        "flux", "fluxcd",
    ],
    "ENDPOINT": [
        "windows workstation", "macbook", "mac",
        "laptop", "desktop", "workstation",
        "endpoint", "agent", "edr",
        "crowdstrike", "sentinelone", "carbon black",
        "windows 10", "windows 11",
        "macos", "osx",
    ],
}


# ── Hostname hints → Role ─────────────────────────────────────────────────
# Enriched: more common naming patterns seen in real infra
ROLE_HOSTNAME_HINTS = {
    "WEB":        ["www", "web", "frontend", "fe", "static", "assets", "cdn", "ui"],
    "API":        ["api", "backend", "be", "svc", "service", "gw", "gateway", "rpc"],
    "DATABASE":   ["db", "database", "mysql", "postgres", "pgsql", "mongo",
                   "redis", "cache", "elastic", "search", "cassandra", "clickhouse"],
    "AUTH":       ["auth", "sso", "iam", "idp", "ldap", "keycloak", "vault", "secrets"],
    "MAIL":       ["mail", "smtp", "imap", "mx", "relay", "exchange"],
    "MANAGEMENT": ["bastion", "jumpbox", "mgmt", "management", "jump",
                   "infra", "ops", "kube", "k8s", "rancher", "control"],
    "MONITORING": ["monitor", "metrics", "grafana", "prometheus", "logs",
                   "logging", "alerting", "tracing", "apm", "observability"],
    "CICD":       ["jenkins", "ci", "cd", "build", "pipeline", "deploy",
                   "argo", "runner", "release", "artifact"],
    "STORAGE":    ["storage", "s3", "blob", "nfs", "backup", "archive",
                   "minio", "ceph", "filer", "nas", "san"],
    "MESSAGE_BUS": ["kafka", "rabbit", "mq", "broker", "queue",
                    "pubsub", "streaming", "event"],
}

# Port-role priority for port-based lookup (first match wins)
_PORT_ROLE_PRIORITY = ["DATABASE", "AUTH", "WEB", "MANAGEMENT", "MAIL", "MESSAGE_BUS"]
# Component-role priority (first match wins)
_COMP_ROLE_PRIORITY = [
    "DATABASE", "AUTH", "MANAGEMENT", "MAIL",
    "STORAGE", "MESSAGE_BUS", "MONITORING", "CICD",
    "ENDPOINT", "WEB", "API",
]


# ── Environment keywords ───────────────────────────────────────────────────
PROD_KEYWORDS = [
    "prod", "production", "prd", "live",
    "release", "stable", "main", "master",   # git-derived naming
    "blue", "green",                          # blue/green deployment names
]
NON_PROD_KEYWORDS = [
    "dev", "develop", "development",
    "test", "testing", "tst",
    "qa", "qe", "quality",
    "uat", "sit", "integration",
    "stage", "staging", "stg", "preprod", "pre-prod", "pre_prod",
    "sandbox", "sbx",
    "demo", "poc", "pilot",
    "lab", "local", "localhost",
    "canary", "alpha", "beta", "nightly",
    "ephemeral", "preview", "feature",
]


# ── Exposure config ────────────────────────────────────────────────────────
EXPOSURE_SCORES = {"PUBLIC": 1.0, "EDGE": 0.8, "PRIVATE": 0.5, "LOCAL": 0.2, "UNKNOWN": 0.5}

# Ports that, even on a private IP, suggest the service faces the outside
EXPOSED_PORT_SET = {
    80, 443, 8080, 8443,   # web
    22,                     # SSH (commonly internet-exposed bastion)
    3389,                   # RDP
    3000,                   # Grafana (sometimes public)
    8888,                   # Jupyter (known risk)
    6443,                   # Kubernetes API
    10250,                  # Kubelet
    9200,                   # Elasticsearch (frequently exposed accidentally)
    5601,                   # Kibana
    27017,                  # MongoDB (famous accidental exposure)
    9092,                   # Kafka
    2181,                   # ZooKeeper
    2379,                   # etcd
}

# Keywords that, inside hostname/component, hint at internet-reachable even on private IP
PUBLIC_HOSTNAME_KEYWORDS = [
    "public", "edge", "proxy", "gateway", "vpn", "internet",
    "dmz", "external", "ext", "lb", "loadbalancer", "load-balancer",
    "ingress", "nat", "egress", "frontend", "reverse-proxy",
    "cdn", "cloudfront", "fastly", "akamai",
]
# Keywords that, only in hostname (not component), imply at least EDGE exposure
PUBLIC_HOSTNAME_ONLY_KEYWORDS = [
    "www", "api", "public", "edge", "gateway", "portal",
    "app", "remote", "access",
]


# ── Cloud patterns ─────────────────────────────────────────────────────────
# Enriched: all major AWS managed service domains, Azure, GCP, common SaaS
CLOUD_PATTERNS = [
    # ── AWS ──────────────────────────────────────────────────────────────
    ("s3.amazonaws.com",              "S3"),
    (".s3.",                          "S3"),          # path-style: bucket.s3.region…
    ("ec2.amazonaws.com",             "COMPUTE"),
    ("ec2.internal",                  "COMPUTE"),     # private EC2 DNS
    ("compute.internal",              "COMPUTE"),
    ("elb.amazonaws.com",             "LOAD_BALANCER"),
    ("alb.amazonaws.com",             "LOAD_BALANCER"),
    ("nlb.amazonaws.com",             "LOAD_BALANCER"),
    ("rds.amazonaws.com",             "MANAGED_DB"),
    ("cluster.local",                 "COMPUTE"),     # k8s in-cluster DNS
    ("iam.amazonaws.com",             "IAM"),
    ("sts.amazonaws.com",             "IAM"),
    ("lambda.amazonaws.com",          "SERVERLESS"),
    ("execute-api.amazonaws.com",     "SERVERLESS"),  # API GW
    ("elasticache.amazonaws.com",     "MANAGED_DB"),
    ("es.amazonaws.com",              "MANAGED_DB"),  # OpenSearch Service
    ("redshift.amazonaws.com",        "MANAGED_DB"),
    ("dynamodb.amazonaws.com",        "MANAGED_DB"),
    ("kinesis.amazonaws.com",         "MESSAGE_BUS"),
    ("sqs.amazonaws.com",             "MESSAGE_BUS"),
    ("sns.amazonaws.com",             "MESSAGE_BUS"),
    ("secretsmanager.amazonaws.com",  "IAM"),
    ("kms.amazonaws.com",             "IAM"),
    ("ssm.amazonaws.com",             "MANAGEMENT"),
    ("eks.amazonaws.com",             "COMPUTE"),
    ("ecr.amazonaws.com",             "STORAGE"),
    ("cloudfront.net",                "LOAD_BALANCER"),
    # ── Azure ─────────────────────────────────────────────────────────────
    ("blob.core.windows.net",         "S3"),
    ("file.core.windows.net",         "STORAGE"),
    ("queue.core.windows.net",        "MESSAGE_BUS"),
    ("table.core.windows.net",        "MANAGED_DB"),
    ("database.windows.net",          "MANAGED_DB"),
    ("documents.azure.com",           "MANAGED_DB"),  # CosmosDB
    ("redis.cache.windows.net",       "MANAGED_DB"),
    ("servicebus.windows.net",        "MESSAGE_BUS"),
    ("eventhub.windows.net",          "MESSAGE_BUS"),
    ("azurewebsites.net",             "SERVERLESS"),
    ("azurecontainer.io",             "COMPUTE"),
    ("azurecr.io",                    "STORAGE"),
    ("vault.azure.net",               "IAM"),
    ("microsoftonline.com",           "IAM"),
    ("login.microsoft.com",           "IAM"),
    ("azure-automation.net",          "MANAGEMENT"),
    ("trafficmanager.net",            "LOAD_BALANCER"),
    ("cloudapp.azure.com",            "COMPUTE"),
    # ── GCP ───────────────────────────────────────────────────────────────
    ("storage.googleapis.com",        "S3"),
    ("cloudfunctions.net",            "SERVERLESS"),
    ("run.app",                       "SERVERLESS"),   # Cloud Run
    ("appspot.com",                   "SERVERLESS"),
    ("compute.googleapis.com",        "COMPUTE"),
    ("gcr.io",                        "STORAGE"),
    ("pkg.dev",                       "STORAGE"),      # Artifact Registry
    ("cloudsql.googleapis.com",       "MANAGED_DB"),
    ("bigtable.googleapis.com",       "MANAGED_DB"),
    ("spanner.googleapis.com",        "MANAGED_DB"),
    ("pubsub.googleapis.com",         "MESSAGE_BUS"),
    ("iamcredentials.googleapis.com", "IAM"),
    ("iam.googleapis.com",            "IAM"),
    ("secretmanager.googleapis.com",  "IAM"),
    ("container.googleapis.com",      "COMPUTE"),      # GKE
]
CLOUD_NONE_LABEL = "NONE"


# ── Dependency config ──────────────────────────────────────────────────────
DEPENDENCY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVEL_TO_SCORE    = {"LOW": 0.25, "MEDIUM": 0.50, "HIGH": 0.75, "CRITICAL": 1.00}
ROLE_BASE_LEVEL   = {
    "AUTH":        "CRITICAL",
    "DATABASE":    "HIGH",
    "API":         "HIGH",
    "WEB":         "MEDIUM",
    "MANAGEMENT":  "HIGH",
    "MAIL":        "MEDIUM",
    "STORAGE":     "HIGH",
    "MESSAGE_BUS": "HIGH",
    "MONITORING":  "MEDIUM",
    "CICD":        "HIGH",
    "ENDPOINT":    "LOW",
    "UNKNOWN":     "MEDIUM",
}

# ── Criticality weights ────────────────────────────────────────────────────
CRIT_W_EXPOSURE   = 0.5
CRIT_W_DEPENDENCY = 0.5
CRIT_ROUND        = 3

print("✓ All mappings loaded")

# %%
# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — INFERENCE FUNCTIONS
# All deterministic logic as plain functions — no class overhead.
# ═══════════════════════════════════════════════════════════════════════════

# ── IP helpers ────────────────────────────────────────────────────────────

def _is_localhost(ip: str) -> bool:
    if not ip:
        return False
    if ip.lower() in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _is_private(ip: str) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_loopback
    except ValueError:
        return False


def _is_public(ip: str) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
        return (
            not a.is_private and not a.is_loopback
            and not a.is_link_local and not a.is_multicast
            and not a.is_unspecified and not a.is_reserved
        )
    except ValueError:
        return False


def _has_kw(keywords: list, *texts) -> bool:
    """True if any keyword appears in any of the given text strings."""
    combined = " ".join(str(t).lower() for t in texts if t)
    return any(kw.lower() in combined for kw in keywords)


# ── Role inference ─────────────────────────────────────────────────────────

def infer_role(hostname: str, ip: str, component: str, port) -> str:
    """Priority: port → component keywords → hostname hints → UNKNOWN."""
    hostname  = (hostname  or "").strip().lower()
    component = (component or "").strip().lower()
    port      = int(port) if port and str(port).strip() not in ("", "nan", "none") else 0

    # 1. Port
    for role in _PORT_ROLE_PRIORITY:
        if port in ROLE_PORT_MAP.get(role, []):
            return role

    # 2. Component
    for role in _COMP_ROLE_PRIORITY:
        if _has_kw(ROLE_COMPONENT_MAP.get(role, []), component):
            return role

    # 3. Hostname
    for role, hints in ROLE_HOSTNAME_HINTS.items():
        if _has_kw(hints, hostname):
            return role

    return "UNKNOWN"


# ── Exposure inference ─────────────────────────────────────────────────────

def infer_exposure(hostname: str, ip: str, component: str, port) -> float:
    """Returns a float in {0.2, 0.5, 0.8, 1.0}."""
    hostname  = (hostname  or "").strip().lower()
    component = (component or "").strip().lower()
    ip        = (ip        or "").strip()
    port      = int(port) if port and str(port).strip() not in ("", "nan", "none") else 0

    # Localhost
    if _is_localhost(ip):
        return EXPOSURE_SCORES["LOCAL"]

    # Definitive public IP
    if ip and _is_public(ip):
        return EXPOSURE_SCORES["PUBLIC"]

    # Private IP — check for edge signals
    if ip and _is_private(ip):
        combined = f"{hostname} {component}"
        if _has_kw(PUBLIC_HOSTNAME_KEYWORDS, combined) or port in EXPOSED_PORT_SET:
            return EXPOSURE_SCORES["EDGE"]
        return EXPOSURE_SCORES["PRIVATE"]

    # No IP — use hostname only
    if not ip:
        if _has_kw(PUBLIC_HOSTNAME_ONLY_KEYWORDS, hostname):
            return EXPOSURE_SCORES["EDGE"]
        # Cloud hostnames → likely reachable from within cloud VPC
        for pat, _ in CLOUD_PATTERNS:
            if pat in hostname:
                return EXPOSURE_SCORES["PRIVATE"]
        return EXPOSURE_SCORES["UNKNOWN"]

    return EXPOSURE_SCORES["UNKNOWN"]


# ── Environment inference ──────────────────────────────────────────────────

def infer_environment(hostname: str, component: str, tags: list) -> str:
    """Returns PROD | NON_PROD | UNKNOWN. PROD wins on conflict."""
    tag_text = " ".join(str(t) for t in (tags or []))
    texts    = [hostname, component, tag_text]
    if _has_kw(PROD_KEYWORDS, *texts):
        return "PROD"
    if _has_kw(NON_PROD_KEYWORDS, *texts):
        return "NON_PROD"
    return "UNKNOWN"


# ── Cloud detection ────────────────────────────────────────────────────────

def detect_cloud(hostname: str) -> str:
    """Returns a cloud service label or NONE."""
    hostname = (hostname or "").strip().lower()
    for pattern, label in CLOUD_PATTERNS:
        if pattern in hostname:
            return label
    return CLOUD_NONE_LABEL


# ── Dependency inference ───────────────────────────────────────────────────

def _apply_modifiers(base: str, ups: int, downs: int) -> str:
    idx = DEPENDENCY_LEVELS.index(base)
    idx = min(idx + ups,   len(DEPENDENCY_LEVELS) - 1)
    idx = max(idx - downs, 0)
    return DEPENDENCY_LEVELS[idx]


def infer_dependency(ip: str, role: str, exposure: float, environment: str, cloud: str) -> tuple:
    """
    Returns (dependency_level: str, dependency_score: float).
    Level: LOW | MEDIUM | HIGH | CRITICAL
    Score: 0.25 | 0.50 | 0.75 | 1.00
    """
    base  = ROLE_BASE_LEVEL.get(role, "MEDIUM")
    is_public   = (exposure == 1.0)
    is_isolated = (exposure == 0.2) or _is_localhost(ip)
    is_internal = (exposure <= 0.5) and (_is_private(ip) or not ip)

    # Upgrades
    ups = 0
    if is_public:                                           ups += 1  # internet-facing
    if environment == "PROD":                               ups += 1  # production weight
    if cloud in ("IAM", "S3"):                              ups += 1  # high-value cloud asset
    if cloud in ("MANAGED_DB", "MESSAGE_BUS"):              ups += 1  # critical cloud infra
    if role in ("MANAGEMENT", "AUTH", "DATABASE") and is_public:  ups += 1  # worst combos
    if role == "CICD" and environment == "PROD":            ups += 1  # prod pipeline = blast radius

    # Downgrades
    downs = 0
    if environment == "NON_PROD":                           downs += 1
    if is_isolated:                                         downs += 1
    if role == "ENDPOINT":                                  downs += 1
    if role in ("MONITORING", "UNKNOWN") and is_internal:   downs += 1  # internal utility
    if role == "MONITORING" and environment == "NON_PROD":  downs += 1  # non-prod monitoring

    level = _apply_modifiers(base, ups, downs)
    return level, LEVEL_TO_SCORE[level]


# ── Criticality formula ────────────────────────────────────────────────────

def compute_criticality(exposure: float, dep_score: float) -> float:
    return round(CRIT_W_EXPOSURE * exposure + CRIT_W_DEPENDENCY * dep_score, CRIT_ROUND)


# ── Full pipeline for one asset ────────────────────────────────────────────

def run_criticality_pipeline(row: dict) -> dict:
    """
    Run all inference stages for a single asset row dict.
    Returns a dict with the computed fields.
    """
    hostname  = str(row.get("hostname",  "") or "")
    ip        = str(row.get("ip",        "") or "")
    component = str(row.get("component", "") or "")
    _raw_port = row.get("port", 0)
    port      = int(float(_raw_port)) if _raw_port and str(_raw_port).strip() not in ("", "nan", "none", "null") else 0
    # tags column may not exist in CSV — derive from hostname+component
    raw_tags  = row.get("tags", None)
    if raw_tags and not (isinstance(raw_tags, float)):
        tags = [t.strip() for t in str(raw_tags).split(",") if t.strip()]
    else:
        tags = []

    role        = infer_role(hostname, ip, component, port)
    exposure    = infer_exposure(hostname, ip, component, port)
    environment = infer_environment(hostname, component, tags)
    cloud       = detect_cloud(hostname)
    dep_level, dep_score = infer_dependency(ip, role, exposure, environment, cloud)
    criticality = compute_criticality(exposure, dep_score)

    return {
        "inferred_role":          role,
        "exposure_score":         exposure,
        "environment":            environment,
        "cloud_type":             cloud,
        "dependency_level":       dep_level,
        "dependency_score":       dep_score,
        "asset_criticality_score": criticality,
    }


print("✓ Inference functions ready")

# %%
# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — LLM FALLBACK
# ═══════════════════════════════════════════════════════════════════════════

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

gemini_client = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    temperature=0,
    api_key=GEMINI_API_KEY
)

# Known roles and environments the LLM must pick from
_VALID_ROLES = [
    "DATABASE", "AUTH", "WEB", "API", "MANAGEMENT", "MAIL",
    "STORAGE", "MESSAGE_BUS", "MONITORING", "CICD", "ENDPOINT", "UNKNOWN"
]
_VALID_ENVS = ["PROD", "NON_PROD", "UNKNOWN"]


_UNRESOLVABLE_EXPOSURE = EXPOSURE_SCORES["UNKNOWN"]   # 0.5, no-signal sentinel


def requires_llm(result: dict) -> bool:
    """
    Fire LLM only when the deterministic pipeline produced zero signal on
    ALL of the inferrable fields. Specifically:
      - role        == UNKNOWN
      - environment == UNKNOWN
      - exposure    == 0.5  (UNKNOWN sentinel — no IP, no hostname hints)
      - cloud_type  == NONE (not a cloud asset, so no cloud-derived env/role)

    If even ONE field resolved, the asset has enough signal — no LLM needed.
    cloud_type NONE is expected for on-prem; it is NOT a trigger by itself.
    """
    return (
        result["inferred_role"]  == "UNKNOWN"
        and result["environment"] == "UNKNOWN"
        and result["exposure_score"] == _UNRESOLVABLE_EXPOSURE
        and result["cloud_type"] == CLOUD_NONE_LABEL
    )


def llm_fill_unknowns(row: dict, result: dict) -> dict:
    """
    Ask the LLM only for fields that are genuinely unresolvable:
      • inferred_role   — if UNKNOWN
      • environment     — if UNKNOWN
    Never ask for exposure_score or cloud_type — those are deterministic.
    Adds instance_id to context.
    """
    need_role = (result["inferred_role"] == "UNKNOWN")
    need_env  = (result["environment"]   == "UNKNOWN")

    if not need_role and not need_env:
        return result  # nothing to ask

    ask_fields = []
    if need_role:
        ask_fields.append(f"role (choose one of: {', '.join(_VALID_ROLES)})")
    if need_env:
        ask_fields.append(f"environment (choose one of: {', '.join(_VALID_ENVS)})")

    # Build context — include instance_id alongside the other identifiers
    context = (
        f"hostname:    {row.get('hostname',    'unknown')}\n"
        f"instance_id: {row.get('instance_id', 'unknown')}\n"   # ← added
        f"ip:          {row.get('ip',          'unknown')}\n"
        f"component:   {row.get('component',   'unknown')}\n"
        f"port:        {row.get('port',        'unknown')}\n"
        f"vuln_id:     {row.get('vuln_id',     'unknown')}\n"
        f"description: {str(row.get('description', ''))[:300]}"
    )

    # Tell the LLM exactly which fields are still open and why
    unresolved_note = (
        "NOTE: deterministic inference found no signal for the fields below. "
        "Only infer what the asset context genuinely supports. "
        "If you cannot determine a field with reasonable confidence, "
        "respond with UNKNOWN for that field — do not guess."
    )

    prompt = (
        "You are a cybersecurity infrastructure analyst.\n"
        f"{unresolved_note}\n\n"
        f"Fields needed: {', '.join(ask_fields)}\n\n"
        f"Asset context:\n{context}\n\n"
        "Respond ONLY with a JSON object. No explanation. Example:\n"
        '{"inferred_role": "API", "environment": "PROD"}'
    )

    try:
        raw = gemini_client.invoke(prompt).content

        if not raw or not raw.strip():
            log.warning("    LLM returned empty response — keeping UNKNOWN")
            raw = None

        if raw:
            raw = raw.strip().replace("```json", "").replace("```", "").strip()
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                log.warning("    LLM response not valid JSON — keeping UNKNOWN")
                data = {}

            if need_role and data.get("inferred_role") in _VALID_ROLES:
                result["inferred_role"] = data["inferred_role"]
            if need_env and data.get("environment") in _VALID_ENVS:
                result["environment"] = data["environment"]

            log.info("    LLM filled: role=%s  env=%s",
                     result["inferred_role"], result["environment"])

    except TimeoutError as e:
        log.warning("    LLM request timed out (%s) — keeping UNKNOWN", e)
    except (ConnectionError, OSError) as e:
        log.warning("    LLM network failure (%s) — keeping UNKNOWN", e)
    except Exception as e:
        log.warning("    LLM fallback failed (%s) — keeping UNKNOWN", e)

    # Re-run dependency + criticality with whatever role/env we now have
    ip = str(row.get("ip", "") or "")
    dep_level, dep_score = infer_dependency(
        ip, result["inferred_role"], result["exposure_score"],
        result["environment"], result["cloud_type"]
    )
    result["dependency_level"]         = dep_level
    result["dependency_score"]         = dep_score
    result["asset_criticality_score"]  = compute_criticality(result["exposure_score"], dep_score)

    return result


print("✓ LLM fallback ready")


# %%
# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — DB helpers
# ═══════════════════════════════════════════════════════════════════════════

# ── Retry helper Function ──────────────────────────────────────────────────────────
_RETRY_ATTEMPTS = 3
_RETRY_DELAY    = 5  # seconds

_TRANSIENT_ERRORS = (psycopg2.OperationalError, ConnectionError, TimeoutError)


def retry(fn, *args, **kwargs):
    """
    Call fn(*args, **kwargs) up to _RETRY_ATTEMPTS times.
    Retries only on transient infrastructure errors.
    Raises on the last failure.
    """
    last_exc = None
    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            return fn(*args, **kwargs)
        except _TRANSIENT_ERRORS as e:
            last_exc = e
            if attempt < _RETRY_ATTEMPTS:
                log.warning("[retry] Attempt %d/%d failed: %s — retrying in %ds",
                            attempt, _RETRY_ATTEMPTS, e, _RETRY_DELAY)
                time.sleep(_RETRY_DELAY)
            else:
                log.error("[retry] All %d attempts failed: %s", _RETRY_ATTEMPTS, e)
    raise last_exc


def _connect():
    return psycopg2.connect(
        host     = os.environ["DB_HOST"],
        port     = int(os.environ.get("DB_PORT", 5432)),
        dbname   = os.environ["DB_NAME"],
        user     = os.environ["DB_USER"],
        password = os.environ["DB_PASSWORD"],
        sslmode  = os.environ.get("DB_SSLMODE", "require"),
        connect_timeout = 10,
    )


def get_conn():
    """Open a DB connection with retry on transient failures."""
    return retry(_connect)


# Batch upsert computed asset context back to DB
def batch_upsert_asset_context(conn, rows: list[dict]) -> None:
    if not rows:
        return
    sql = """
        INSERT INTO assets (
            asset_id, inferred_role, exposure_score, environment,
            cloud_type, dependency_level, dependency_score,
            asset_criticality_score, first_seen, last_seen
        ) VALUES (
            %(asset_id)s, %(inferred_role)s, %(exposure_score)s, %(environment)s,
            %(cloud_type)s, %(dependency_level)s, %(dependency_score)s,
            %(asset_criticality_score)s,
            COALESCE(%(first_seen)s::timestamptz, now()),
            %(last_seen)s::timestamptz
        )
        ON CONFLICT (asset_id) DO UPDATE SET
            inferred_role           = EXCLUDED.inferred_role,
            exposure_score          = EXCLUDED.exposure_score,
            environment             = EXCLUDED.environment,
            cloud_type              = EXCLUDED.cloud_type,
            dependency_level        = EXCLUDED.dependency_level,
            dependency_score        = EXCLUDED.dependency_score,
            asset_criticality_score = EXCLUDED.asset_criticality_score,
            first_seen              = COALESCE(assets.first_seen, EXCLUDED.first_seen),
            last_seen               = EXCLUDED.last_seen
    """
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows)
    conn.commit()

print("✓ DB helpers ready")


# %%
# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — LANGGRAPH STATE + NODES
# ═══════════════════════════════════════════════════════════════════════════

class CriticalityState(TypedDict):
    working_csv:    str
    status:         str           # running | done | error
    error:          Optional[str]
    processed:      int           # new assets computed
    skipped:        int           # existing assets (already had scores)
    llm_calls:      int           # how many LLM fallbacks were triggered


_cache: dict = {}  # in-process cache shared across nodes


# ── Node 1: load_csv ──────────────────────────────────────────────────────

def load_csv(state: CriticalityState) -> CriticalityState:
    _cache.clear()
    log.info("[load_csv] Reading %s", state["working_csv"])
    try:
        df = pd.read_csv(state["working_csv"])
        df.columns = [c.strip().lower() for c in df.columns]
        
        # Reference cleanup
        if "references" in df.columns:
            log.info("[reference_filter] Cleaning references...")
            df["references"] = df["references"].apply(
                filter_important_references
            )
        
        log.info("  → %d rows, columns: %s", len(df), list(df.columns))
        _cache["df"] = df
        return {**state, "status": "running"}
    except Exception as e:
        return {**state, "status": "error", "error": str(e)}


# Function to clean references to keep only important references
IMPORTANT_PATTERNS = [
    r"access\.redhat\.com",
    r"nvd\.nist\.gov",
    r"usn\.ubuntu\.com",
    r"debian\.org",
    r"security-tracker\.debian\.org",
    r"security\.gentoo\.org",
    r"msrc\.microsoft\.com",
    r"security\.netapp\.com",
    r"support\.f5\.com",
    r"oracle\.com",
    r"cert-portal\.siemens\.com",
    r"rustsec\.org",
    r"snyk\.io",
    r"hackerone\.com",

    # Github
    r"github\.com/.*/commit/",
    r"github\.com/.*/releases/",
    r"github\.com/.*/security/advisories/",
    r"GHSA-"
]


def filter_important_references(reference_string):
    if pd.isna(reference_string):
        return reference_string

    reference_string = str(reference_string)

    # Extract URLs
    urls = re.findall(r'https?://[^\s,\]\["\']+', reference_string)

    important_urls = []

    for url in urls:
        if any(
            re.search(pattern, url, re.IGNORECASE)
            for pattern in IMPORTANT_PATTERNS
        ):
            important_urls.append(url)

    # Remove duplicates preserving order
    important_urls = list(dict.fromkeys(important_urls))

    return ";".join(important_urls)


# ── Node 2: compute_criticality_for_new ──────────────────────────────────
_llm_semaphore = threading.Semaphore(1)   # one LLM call at a time
_llm_lock      = threading.Lock()          # protects llm_call_count increment
def compute_criticality_for_new(state: CriticalityState) -> CriticalityState:
    if state["status"] == "error":
        return state

    df = _cache["df"]

    # Ensure all output columns exist (add timestamp cols too)
    for col in ["inferred_role", "exposure_score", "environment",
                "cloud_type", "dependency_level", "dependency_score",
                "asset_criticality_score", "first_seen", "last_seen"]:
        if col not in df.columns:
            df[col] = None

    text_cols = ["inferred_role", "environment", "cloud_type", "dependency_level"]
    df[text_cols] = df[text_cols].astype("object")

    required_cols = [
        "inferred_role", "exposure_score", "environment", "cloud_type",
        "dependency_level", "dependency_score", "asset_criticality_score"
    ]

    needs_work = (
        df[df[required_cols].isna().any(axis=1)]
        .drop_duplicates(subset=["asset_id"])
        .copy()
    )

    already_done = df["asset_id"].nunique() - len(needs_work)
    log.info("[compute_criticality] %d new assets to process, %d already scored",
             len(needs_work), already_done)

    llm_call_count = 0
    results: dict = {}
    now = datetime.now(timezone.utc).isoformat()

    def _process(row_dict, asset_id):
        result = run_criticality_pipeline(row_dict)
        used_llm = False
        if requires_llm(result):
            log.info("  [LLM] asset_id=%s  role=%s  env=%s — invoking LLM",
                     asset_id, result["inferred_role"], result["environment"])
            with _llm_semaphore:
                time.sleep(0.5)
                result = llm_fill_unknowns(row_dict, result)
            used_llm = True

        # ── PATCH: stamp timestamps into the result dict ──────────────
        existing_first_seen = row_dict.get("first_seen")
        result["first_seen"] = (
            existing_first_seen
            if existing_first_seen and str(existing_first_seen).strip() not in ("", "nan", "none", "null")
            else now
        )
        result["last_seen"] = now
        # ─────────────────────────────────────────────────────────────

        return result, used_llm

    work_items = []
    for _, row in needs_work.iterrows():
        asset_id = row.get("asset_id")
        if not asset_id or str(asset_id).strip() in ("", "nan", "none"):
            log.warning("  Skipping row with no asset_id: hostname=%s", row.get("hostname"))
            continue
        work_items.append((row.to_dict(), str(asset_id)))

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_process, row_dict, asset_id): asset_id
            for row_dict, asset_id in work_items
        }
        for future in as_completed(futures):
            asset_id = futures[future]
            try:
                result, used_llm = future.result()
                results[asset_id] = result
                if used_llm:
                    with _llm_lock:
                        llm_call_count += 1
                log.info("  ✓ %s → role=%s env=%s crit=%.3f",
                         asset_id, result["inferred_role"], result["environment"],
                         result["asset_criticality_score"])
            except Exception as e:
                log.error("  ✗ asset_id=%s failed: %s — skipping", asset_id, e)

    output_cols = [
        "inferred_role", "exposure_score", "environment",
        "cloud_type", "dependency_level", "dependency_score",
        "asset_criticality_score", "first_seen", "last_seen",  # ← PATCH: added
    ]
    for i, row in df.iterrows():
        aid = str(row.get("asset_id", "") or "").strip()
        if aid in results:
            for col in output_cols:
                df.at[i, col] = results[aid][col]

    _cache["df"]      = df
    _cache["results"] = results
    return {**state, "processed": len(results), "skipped": already_done, "llm_calls": llm_call_count}

# ── Node 3: upsert_to_db ──────────────────────────────────────────────────
# DB is the source of truth — upsert succeeds BEFORE CSV is written.
# Retry 3 times with 5s delay. On failure: rollback, stop agent, raise error.

def upsert_to_db(state: CriticalityState) -> CriticalityState:
    if state["status"] == "error":
        return state

    df      = _cache["df"]
    results = _cache.get("results", {})
    now     = datetime.now(timezone.utc).isoformat()

    upsert_rows = []
    seen_ids    = set()

    def _clean_ts(val) -> Optional[str]:
        """Return val if it looks like a real timestamp string, else None."""
        if val is None:
            return None
        s = str(val).strip()
        if s.lower() in ("", "nan", "none", "null", "nat"):
            return None
        return s

    for _, row in df.drop_duplicates(subset=["asset_id"]).iterrows():
        aid = str(row.get("asset_id", "") or "").strip()
        if not aid or aid in ("nan", "none", ""):
            continue
        if aid in seen_ids:
            continue
        seen_ids.add(aid)

        # For newly computed assets, pull timestamps from results{}.
        # For skipped (existing) assets, results{} has no entry —
        # first_seen comes from the CSV (already in DB), last_seen = now.
        res = results.get(aid, {})

        first_seen = _clean_ts(res.get("first_seen")) \
                     or _clean_ts(row.get("first_seen"))
        # first_seen may still be None for brand-new assets that had no
        # prior CSV value — SQL COALESCE will write `now` on insert and
        # keep the existing value on conflict.

        last_seen = _clean_ts(res.get("last_seen")) or now

        upsert_rows.append({
            "asset_id":                aid,
            "inferred_role":           row.get("inferred_role"),
            "exposure_score":          row.get("exposure_score"),
            "environment":             row.get("environment"),
            "cloud_type":              row.get("cloud_type"),
            "dependency_level":        row.get("dependency_level"),
            "dependency_score":        row.get("dependency_score"),
            "asset_criticality_score": row.get("asset_criticality_score"),
            "first_seen":              first_seen,   # None → COALESCE handles it
            "last_seen":               last_seen,    # always a real timestamp
        })

    log.info("[upsert_to_db] Upserting %d asset rows", len(upsert_rows))
    conn = None
    try:
        def _do_upsert():
            nonlocal conn
            conn = get_conn()
            batch_upsert_asset_context(conn, upsert_rows)
            conn.close()
            conn = None
        retry(_do_upsert)
        log.info("  → DB upsert complete")
    except Exception as e:
        if conn is not None:
            try: conn.rollback()
            except Exception: pass
            try: conn.close()
            except Exception: pass
        log.error("[upsert_to_db] Failed after retries: %s", e)
        return {**state, "status": "error", "error": str(e)}

    _cache["upsert_rows_done"] = True
    return state

# ── Node 4: write_results_to_csv ──────────────────────────────────────────
# Only runs after upsert_to_db succeeds.

def write_results_to_csv(state: CriticalityState) -> CriticalityState:
    if state["status"] == "error":
        return state

    df      = _cache["df"]
    results = _cache["results"]
    now     = datetime.now(timezone.utc).isoformat()

    output_cols = [
        "inferred_role", "exposure_score", "environment",
        "cloud_type", "dependency_level", "dependency_score",
        "asset_criticality_score", "first_seen", "last_seen",
    ]

    for i, row in df.iterrows():
        aid = str(row.get("asset_id", "") or "").strip()
        if aid in results:
            # Newly computed asset — write all fields including both timestamps
            for col in output_cols:
                df.at[i, col] = results[aid][col]
        else:
            # Skipped (existing) asset — only refresh last_seen
            df.at[i, "last_seen"] = now

    try:
        df.to_csv(state["working_csv"], index=False)
        log.info("[write_results_to_csv] Saved %d rows → %s", len(df), state["working_csv"])
        _cache["df"] = df
    except Exception as e:
        return {**state, "status": "error", "error": str(e)}

    return {**state, "status": "done"}


print("✓ LangGraph nodes defined")


# %%
# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — BUILD AND COMPILE THE GRAPH
# Node order: load_csv → compute_criticality_for_new → upsert_to_db → write_results_to_csv
# DB is updated before CSV — database is the source of truth.
# ═══════════════════════════════════════════════════════════════════════════

def route(state: CriticalityState) -> str:
    return "error_end" if state["status"] == "error" else "continue"


builder = StateGraph(CriticalityState)

builder.add_node("load_csv",                    load_csv)
builder.add_node("compute_criticality_for_new",  compute_criticality_for_new)
builder.add_node("upsert_to_db",                upsert_to_db)
builder.add_node("write_results_to_csv",         write_results_to_csv)

builder.set_entry_point("load_csv")

builder.add_conditional_edges(
    "load_csv",
    route,
    {"continue": "compute_criticality_for_new", "error_end": END}
)
builder.add_conditional_edges(
    "compute_criticality_for_new",
    route,
    {"continue": "upsert_to_db", "error_end": END}   # DB first
)
builder.add_conditional_edges(
    "upsert_to_db",
    route,
    {"continue": "write_results_to_csv", "error_end": END}  # CSV only after DB succeeds
)
builder.add_edge("write_results_to_csv", END)

criticality_graph = builder.compile()
print("✓ Graph compiled")

# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE RUN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    initial_state: CriticalityState = {
        "working_csv": "backend/normalized_output/working.csv",
        "status": "running",
        "error": None,
        "processed": 0,
        "skipped": 0,
        "llm_calls": 0,
    }

    final_state = criticality_graph.invoke(initial_state)

    print("\n=== Asset Criticality Agent — Final State ===")
    print(json.dumps(final_state, indent=2))