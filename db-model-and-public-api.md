| Reviewers | Date | Comments |
| --- | --- | --- |
| @Eran Kampf  |  |  |
| @Lior Rozner  |  |  |

This spec outlines changes to support upstream configuration via GAT for PAM resources.

# Models

There are 2 key design decisions in extending the Resource model

- Port restriction.
    - Reuse the port restriction but restrict to TCP + a single port. Disable UDP + ICMP.
    - The alternative is to ignore `Resource.ports` property for PAM resource and store the downstream port in another place. SDWAN still expects the `Resource.ports` property in SD.
- Gateway metadata like downstream, upstream and protocol specific configuration.
    - Use JSON field instead of normalizing to DB columns.
        - Pros: Faster implementation (simpler DB queries). The audit log is also using JSON dict for PAM properties like Gateway ID.
        - Cons: Loses DB schema validation and indexing.
    - Repurposing the `metadata` JSON field that is currently marked for deletion.
        - Steps
            - Migrate all the data to `NetworkResourceMetadata`
            - Remove `KubernetesResourceMetadata` Pydantic.
            - Add new metadata types for SSH and WebApp and migrate the data for those resources type
        - Alternative: create a new `gateway_metadata` JSON by remove the `Kubenertes` and slowly migrating them. We still need to do data migration.

## All PAM resources

- Validate the port restriction
    - Only TCP + single is allowed
    - UDP is restricted
    - ICMP is disallowed.
- Default port to the protocol port
    - Kubernetes: `443`
    - SSH: `22`
    - Webapp: `80`
        - When HTTPS is supported, default to `443` for HTTPS and `80` for HTTP
    - Postgres: `5432`
- Add `gateway_metadata` field — a per-type discriminated union (one Pydantic model per PAM type).

```python
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field

class ResourceType(str, Enum):
    NETWORK = "NETWORK"
    KUBERNETES = "KUBERNETES"
    SSH = "SSH"
    WEB_APP = "WEB_APP"
    POSTGRES = "POSTGRES"  # future

class NetworkGatewayMetadata(BaseModel):
    """Default for non-PAM (NETWORK) resources — no gateway upstream config."""

    type: Literal[ResourceType.NETWORK] = ResourceType.NETWORK

# Per-type models (KubernetesGatewayMetadata, SSHGatewayMetadata, ...) are defined
# in their sections below.
GatewayMetadata = Annotated[
    NetworkGatewayMetadata
    | KubernetesGatewayMetadata
    | SSHGatewayMetadata
    | WebAppGatewayMetadata
    | PostgresGatewayMetadata,
    Field(discriminator="type"),
]

class Resource(models.Model):
    # ... existing fields: type, address, aliases, ports, gateway, ...

    gateway_metadata: GatewayMetadata = SchemaField(
        default_factory=NetworkGatewayMetadata,
        db_default=NetworkGatewayMetadata().model_dump(),  # {"type": "NETWORK"}
    )
```

## Kubernetes Resource

```python
class KubernetesGatewayMetadata(BaseModel):
    type: Literal[ResourceType.KUBERNETES] = ResourceType.KUBERNETES
    # References a cluster in the gateway config (`kubernetes.clusters[].name`).
    # None => gateway runs in-cluster and uses its mounted service-account token + CA.
    cluster_ref: str | None = None
```

## SSH Resource

```python
class SSHUsername(BaseModel):
    username: str
    # Optional — omit when OS users are not dynamically provisioned.
    uid: int | None = None
    gid: int | None = None
    groups: list[str] = Field(default_factory=list)

class SSHGatewayMetadata(BaseModel):
    type: Literal[ResourceType.SSH] = ResourceType.SSH
    # Allowed usernames for this resource. Empty => fall back to the default
    # username in the gateway config. The per-user subset is computed at GAT time
    # from the groups granting access (see AuthZ / GAT). Inline definitions, not a
    # reference, so no Ref suffix.
    usernames: list[SSHUsername] = Field(default_factory=list)
```

## Web App Resource

```python
class WebAppDownstream(BaseModel):
    # Downstream (client-facing) port is `Resource.ports` — the single source of
    # truth — so it is intentionally NOT duplicated here.
    tls: bool = False  # browser-facing TLS; default flips to True once HTTPS is supported

class WebAppUpstream(BaseModel):
    port: int = 443
    tls: bool = True
    ca_ref: str | None = None  # references `cas[].name` in the gateway config

class WebAppGatewayMetadata(BaseModel):
    type: Literal[ResourceType.WEB_APP] = ResourceType.WEB_APP
    downstream: WebAppDownstream = Field(default_factory=WebAppDownstream)
    upstream: WebAppUpstream = Field(default_factory=WebAppUpstream)

    header_rewrites: dict[str, str] = Field(default_factory=dict)
```

## Postgres Resource (future)

```python
class PostgresDownstream(BaseModel):
    # Downstream port is `Resource.ports`. Not duplicated here.
    tls: bool = False

class PostgresUpstream(BaseModel):
    port: int = 5432
    tls: bool = True
    ca_ref: str | None = None  # references `cas[].name` in the gateway config

class PostgresGatewayMetadata(BaseModel):
    type: Literal[ResourceType.POSTGRES] = ResourceType.POSTGRES
    downstream: PostgresDownstream = Field(default_factory=PostgresDownstream)
    upstream: PostgresUpstream = Field(default_factory=PostgresUpstream)

    role_refs: list[str] = Field(default_factory=list)
```

# Audit log

Builds on the SSH Controller tech spec, which adds `gateway: {id, address}` to the Resource's
`data.metadata`. Extend that same `metadata` object with the `gateway_metadata` config (camelCase)
so admin changes are auditable.

Log references only, never secrets: `caRef` is a CA name and `roleRefs` are role names (their
credentials live in the gateway config).

## SSH

```json
{
  "type": "Resource",
  "version": "1.0",
  "id": "UmVzb3VyY2U6MzMK",
  "name": "SSH Server",
  "data": {
    "resourceType": "SSH",
    "metadata": {
      "gateway": {
        "id": "R2F0ZXdheTo5Nwo=",
        "address": "proxy.int:22"
      },
      "usernames": [
        {
          "username": "admin",
          "uid": 123,
          "gid": 123,
          "groups": ["sudo", "docker"]
        },
        {
          "username": "developer",
          "uid": 456,
          "gid": 456,
          "groups": ["docker"]
        }
      ]
    }
  }
}
```

## Web App

```json
{
  "type": "Resource",
  "version": "1.0",
  "id": "UmVzb3VyY2U6MzIK",
  "name": "ACME App",
  "data": {
    // Existing fields ...
    "resourceType": "WebApp",
    "metadata": {
      "gateway": {
        "id": "R2F0ZXdheTo5Nwo=",
        "address": "proxy.int:443"
      },
      "downstream": {
        "tls": true
      },
      "upstream": {
        "port": 8000,
        "tls": false,
        "caRef": "ca1"
      },
      "headerRewrites": {
        "X-ACME-TOKEN": "{{twingate.jwt}}"
      }
    }
  }
}
```

## Postgres (future)

```json
{
  "type": "Resource",
  "version": "1.0",
  "id": "UmVzb3VyY2U6MzQK",
  "name": "Analytics DB",
  "data": {
    "resourceType": "Postgres",
    "metadata": {
      "gateway": {
        "id": "R2F0ZXdheTo5Nwo=",
        "address": "proxy.int:5432"
      },
      "downstream": {
        "tls": true
      },
      "upstream": {
        "port": 5432,
        "tls": true,
        "caRef": "ca1"
      },
      "roleRefs": ["admin", "developer"]
    }
  }
}
```

# AuthZ (GAT)

When calculating GAT, return relevant upstream and downstream informations. See Gateway config and GAT .

# 🚧 Private API

TBD - Waiting for UI changes

# Public API

- Only expose downstream and upstream ports for Web App resource at the moment.
- (Optional?) Remove `ports` restriction field for PAM resources

## Kubernetes

```graphql
type KubernetesResource implements Node & Resource & Taggable {
  id: ID!

	gateway: Gateway!

  clusterRef: String  # References the cluster config defined in Gateway. When null, use in-cluster credentials.
}

type Mutation {
  kubernetesResourceCreate(
    # Remove `protocols` input
    # Add
    clusterRef: String
  ): KubernetesResourceCreateMutation

  kubernetesResourceUpdate(
    # Remove `protocols` input
    # Add
    clusterRef: String
  ): KubernetesResourceUpdateMutation
}
```

## SSH

```graphql
type UserSSHMetadata {
  username: String!
  uid: Int
  gid: Int
}

type User {
  # Other fields
  sshUsername: UserSSHMetadata
}

type SSHUsername {
  username: String!
  # The following fields are optional. They can be omitted if OS user are not provision dynamically.
  uid: Int
  gid: Int
  groups: [String!]! = []
}

type SSHResource implements Node & Resource & Taggable {
	id: ID!
	gateway: Gateway!

  usernames: [SSHUsername!]! = []
}

type AccessEdge {
  # Other fields
  sshUsernames: [SSHUsername!]! = []
}

# No change in mutation yet until we decide what to do with usernames
```

## Web App

```graphql
type WebAppResourceDownstream {
  port: Int = 80
  tls: Boolean = false  # Change the default to `true` when HTTPS is supported
}

type WebAppResourceUpstream {
  port: Int = 443
  tls: Boolean = true
  caRef: String  # Referencing a CA in Gateway config
}

type KeyValuePair {
  key: String!
  value: String!
}

type WebAppResource implements Node & Resource & Taggable {
  id: ID!

  gateway: Gateway!

  downstream: WebAppResourceDownstream!
  upstream: WebAppResourceUpstream!

  headerRewrites: [KeyValuePair!]! = []
}

input WebAppDownstreamInput {
  port: Int!
  tls: Boolean = False
}

input WebAppUpstreamInput {
  port: Int!
  tls: Boolean = False
  caRef: String
}

input KeyValueInput {
	key: String!
	value: String!
}

type Mutation {
  webAppResourceCreate(
    # Remove `protocols` input
    # Add
    downstrem: WebAppDownstreamInput
    upstream: WebAppUpstreamInput
    headerRewrites: [KeyValueInput!]
  ): KubernetesResourceCreateMutation

  webAppResourceUpdate(
    # Remove `protocols` input
    # Add
    downstrem: WebAppDownstreamInput
    upstream: WebAppUpstreamInput
    headerRewrites: [KeyValueInput!]
  ): KubernetesResourceUpdateMutation
}
```

## Postgres (future)

```graphql
type PostgresResourceDownstream {
  port: Int = 5432
  tls: Boolean = false  # Change the default to `true` when TLS is supported
}

type PostgresResourceUpstream {
  port: Int = 5432
  tls: Boolean = true
  caRef: String  # Referencing a CA in Gateway config
}

type PostgresResource implements Node & Resource & Taggable {
  id: ID!

  gateway: Gateway!

  downstream: PostgresResourceDownstream!
  upstream: PostgresResourceUpstream!

  roleRefs: [String!]! = []  # References the role defined in the Gateway.
}

type AccessEdge {
  # Other fields
  postgresRoleRefs: [String!]! = []  # References the role defined in the Gateway.
}
```
