# Hosting

The `snet` network can be used to host services, such as files, websites, servers or applications. Hosting a service
involves making it accessible to other nodes in the network while ensuring security, reliability and anonymity. When
hosting, both the `provider` and the `consumer` roles nodes remain anonymous, through a system known as `broker` nodes.

## Hosting Model

Using a HTTPS server as an example, the hosting model works as follows:

1. The `provider` node sets up a HTTPS server, and creates a service descriptor, which includes the service's public
   key, identifier, and any other relevant metadata. The `provider` node then determines the "resource key" of this
   service, using the standard DHT algorithm.
2. The `provider` node then discovers `broker` nodes in the network, which are nodes whose are "closest" to the resource
   key. Again, a standard DHT algorthm is provided for consistent distance calculations. These broker nodes are stored
   in a temporary cache.
3. The `provider` node then establishes secure, authenticated connections to each of the `broker` nodes using the
   end-to-end tunnel protocol. Using tunneling is important, because it allows for the `provider` node to remain
   anonymous. The `broker` node will then agree to host the service on behalf of the `provider` node.
4. The `provider` node then sends the service descriptor to each of the `broker` nodes, so that the broker node is aware
   of what it is advertising. This is all fully anonymized, so the `provider` doesn't leak any information about itself.
5. The `consumer` node, when it wants to access the service, will compute the resource key for the service, and discover
   the `broker` nodes in the same way as the `provider` node did.
6. The `consumer` node then establishes secure, authenticated connections to each of the `broker` nodes using the
   end-to-end tunnel protocol, ensuring anonymity for itself as well.
7. The `consumer` node then requests the service from the `broker` nodes, via the `consumer<->broker` tunnel. The
   `broker` node will then forward the request to the `provider` node via the `broker<->provider` tunnel.
8. The `provider` node processes the request, and sends the response back to the `broker` node, which then forwards it
   back to the `consumer` node. The `provider` maintains a tunnel mapping table to ensure that responses are sent back
   to the correct `consumer` node.

### Provider node

The provider node is responsible for hosting the service and ensuring that it is accessible to `consumer` nodes via
`broker` nodes. The `provider` node must that it stays online. The availability of the service doesn't come from
sharing the hosting, but rather from hiding the `provider` node's identity behind multiple `broker` nodes.

To prevent random nodes being providers for non-existing services, the `provider` node must complete a very long proof
of work challenge when creating a service (it will take days to compute, and is dependent on the power of the service),
so supercomputers cannot compute massive numbers of fake services. This proof of work is included in the service
descriptor, and is verified by `broker` nodes when they receive the service descriptor, and is linked to the service's
identifier as-well. The descriptor is signed by the service's public key, so broker nodes cannot modify it.

## Maintaining security via broker node.

Once a `consumer` node connects to a `broker` node, all communication between the `consumer` and `provider` needs to be
authenticated and confidential. Looking at other protocols, we see that:

- `e2e connection`: bilateral authentication is possible; both nodes know each other's identity.
- `tunnel connection`: unilateral authentication is possible; only the `client` node knows the `route` nodes'
  identities.

However, in this case neither the `consumer` nor the `provider` nodes can know each other's identities, to maintain
anonymity. What happens is that the `provider` uses the _service's_ private key to sign a hash of the entire resource
being sent. This is used to form a handshake between the `consumer` and `provider`, via the `broker` node, ensuring that
the data is authentic and has not been tampered with. It re-uses the tunnel connection's unilateral authentication
handshake protocol to achieve this. Note that because the identity is always the hash of a public key, the `consumer`
node can verify the signature using the service's public key, whilst checking without doubt that the public key
corresponds to the service it is trying to access.

## Broker node confirmation

A `provider` includes a challenge in the handshake with a `broker` node, following a tunnel setup, which requires the
`broker` node to use a "proof of work" algorithm to solve. This proof of work is designed to prevent Sybil attacks,
where an attacker creates multiple fake identities to overwhelm the network. The challenge is a computational puzzle
that requires significant processing power to solve, but is easy for other nodes to verify. The `broker` node must solve
the challenge and return the solution to the `provider` node as part of the handshake process. This ensures that the
`broker` node is a legitimate participant in the network and has invested resources to prove its authenticity.

## Broker node rotation

To maintain anonymity and security, `broker` nodes should be rotated periodically. This seems difficult, as `consumer`
nodes need to be able to identify `broker` nodes, but there is a simple solution. The resource key is instead calculated
using the following formula:

```
ResourceKey = Hash(ServiceIdentity || EpochNumber)
```

Where the `EpochNumber` is a time-based value that changes periodically (e.g., every hour or day). This means that both
`provider` and `consumer` nodes will compute different resource keys at different times, leading them to discover
different sets of `broker` nodes. This rotation helps to enhance security and anonymity.

## Internal Tunnels

Standard tunnels are created between the `provider` and `broker` nodes, and between the `consumer` and `broker` nodes.
However, additional tunnels are needed; one between the `service` and the `broker`, and one between the `service` and
the `consumer`. Given both the `broker` and `consumer` nodes can authenticate the `service` using its public key, these
tunnels are effectively the `Layer4` connection protocol abstracted over the existing `Layer2` tunnels. This means that
the `service` can be treated as a separate entity, with its own identity and authentication mechanisms, while still
leveraging the existing tunnel infrastructure for secure communication. The `provider` remains an anonymous host for the
`service`, while the `consumer` can securely interact with the `service` through the established tunnels.

---

## Flow

1. The `provider` node will use `Layer2`, to create a route. Rather than the usual 3 hops, it chooses 4 hops, but
   specifically sets the final node to be the broker node. This creates tunnel keys in the usual way, but fixes the
   final hop.
2. The `provider` node then sends a `Layer3_HostServiceRequest` message to the broker node, via the route. This message
   contains the service descriptor, including the service's public key, identifier, proof of work, and any other
   relevant metadata.
3. The `broker` node verifies the service descriptor, **including checking the proof of work**, and stores the service
   descriptor in its local database.
4. The `broker` node sends a `Layer3_HostServiceResponse` message back to the `provider` node, confirming it is hosting
   the service. If the `broker` node cannot host the service (already hosting too many services, invalid descriptor,
   etc), it sends a `Layer3_HostServiceError` message instead.
5. The `consumer` node will use `Layer2`, to create a route to the service, again choosing 4 hops, with the final hop
   being the broker node. This creates tunnel keys in the usual way, but fixes the final hop.
6. The `consumer` node then sends a `Layer3_RequestService` message to the broker node, via the route. This message
   contains the service identifier and any other relevant request parameters, including an ephemeral public key. No
   signature is included here, as this would de-anonymize the consumer. This mirrors `Layer2_TunnelRequest`.
7. The `broker` node looks up the service descriptor in its local database, and if found, forwards the request to the
   `provider` node via the existing tunnel, with the connection token included.
8. The first message that the `consumer` sends will be to start the handshake with the `provider` node, via the
   `broker`. This connection can only use unilateral authentication, as the `provider` doesn't know the `consumer`
   nodes.
9. The `provider` node processes the request, and creates the handshake response. This handshake follows the standard
   tunnel key encapsulation protocol, mirroring the `Layer2_TunnelAccept` message, but using the service's private key
   for the authentication signature. The response includes the connection token the `broker` sent, for mapping.
10. The `broker` node receives the response from the `provider` node, and forwards it back to the `consumer` node via
    the existing tunnel; multiple tunnels will likely exist for the broker, so the node is selected based off of the
    connection token.
11. The `consumer` node receives the handshake response, and verifies the signature using the service's public key from
    the service descriptor. If the verification is successful, the `consumer` node can then proceed to communicate
    securely with the service via the established tunnel (decapsulating the tunnel keys as normal).
12. An authenticated e2e encrypted tunnel now exists between the `consumer` node, and the service hosted by the
    `provider` node, via the `broker` node. All communication between the `consumer` and the service is encrypted and
    authenticated, ensuring confidentiality and integrity.
