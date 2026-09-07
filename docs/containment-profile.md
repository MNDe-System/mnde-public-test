# Strict AI-Agent Containment Profile

MNDe's strict containment profile blocks routed agent actions that could cross a
sandbox boundary, establish persistence, hide activity, communicate with other
agents, reach external systems, or obtain credentials and model weights.

This profile is an **independent executor gate**. An ordinary policy `ALLOW`
cannot override it.

## Threats addressed

The blocked capability classes cover the paths used in documented containment
failures and the adjacent paths needed to make an escape durable:

- public-network egress and network listeners;
- shared filesystem or inter-agent communication;
- credential, secret, host, and control-plane access;
- package installation and child-process creation;
- sandbox, monitoring, and audit modification;
- persistence and external publication; and
- reading or modifying model weights.

Strict mode also refuses an unregistered tool, an unknown capability label, a
missing manifest, or a malformed manifest. This makes new integrations deny by
default instead of silently inheriting authority.

## Enable it

Use the included manifest as a starting point:

```text
MNDE_CONTAINMENT_MODE=strict
MNDE_CONTAINMENT_MANIFEST=./sample-policies/containment-manifest.strict.json
```

The manifest is owned by the operator, not supplied by the agent:

```json
{
  "schema_version": "mnde.containment-manifest.v1",
  "tools": {
    "read_status": ["observability.read"],
    "workspace_read": ["filesystem.read.private"]
  }
}
```

Only these capabilities are accepted in strict mode:

- `compute.local`
- `filesystem.read.private`
- `filesystem.write.private`
- `memory.session`
- `observability.read`

The executor snapshots the manifest when it starts. For every accepted action it
creates containment evidence containing the action, sorted capability list, and
manifest digest. The sidecar includes that evidence in the canonical request,
and therefore in the signed receipt. Immediately before running the function,
the executor verifies that the receipt contains the exact evidence it created.
A request override cannot replace the reserved evidence.

## Refusal codes

| Code | Meaning |
| --- | --- |
| `ERR_CONTAINMENT_MANIFEST_INVALID` | Strict mode has no valid operator manifest. |
| `ERR_CONTAINMENT_TOOL_UNREGISTERED` | The requested tool is absent from the manifest. |
| `ERR_CONTAINMENT_CAPABILITY_BLOCKED` | The tool requires an escape-enabling capability. |
| `ERR_CONTAINMENT_RECEIPT_MISMATCH` | The signed receipt dropped or changed the assessed evidence. |

## Required deployment boundary

Strict mode is one control in a containment system. It does not create a VM,
container, firewall, or operating-system reference monitor. A deployment that
claims containment must also:

1. Route every agent-controlled effect through an enforcing MNDe executor or
   proxy. Do not leave raw tool references available to the agent.
2. Enforce default-deny network policy outside the agent process. Package
   mirrors, metadata endpoints, proxies, DNS, and loopback services are egress
   paths and must be covered.
3. Give each agent a private filesystem and identity. Do not share writable
   caches, package repositories, logs, queues, or credentials between agents.
4. Keep secrets, model weights, monitoring, the kill switch, and MNDe's own
   authority material outside the agent's security principal.
5. Run MNDe and the OS/network controls under a separate operator identity. An
   agent that can edit its manifest, wrapper, policy, or firewall is not
   contained.

If an effect bypasses MNDe, strict mode cannot see or block it. The defensible
claim is therefore: **strict mode refuses escape-class capabilities for actions
routed through an enforcing MNDe integration and bound to a valid operator
manifest.**

