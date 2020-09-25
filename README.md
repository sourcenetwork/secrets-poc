# Secrets Proof-of-Concept

This is the Source Secrets Management Engine Proof-of-Concept repository. It extends the [dkg-experiment](https://github.com/sourcenetwork/dkg-experiment) repo by properly utilizing LibP2P instead of Noise P2P, and by utilizing an async initialization method, compared to the previous sync method.

## How it works
When a node is first started, it is given a list of peers to form a `Secret Ring` with. This `Secret Ring` is a Pederson DKG group that maintains a public key, with each member of the DKG posessing their respective share of the private key.

This implementation uses a redezvous discovery mechanism instead of requiring a single node to be initiated first, and the remaining nodes follow. Rendezvous discovery allows for a more decentralized initialization process with less coordination. As long as all the peers have the appropriate peers.json file, and eventually come online, the DKG will properly initialize.

The DKG implementation is adapted from the [Kyber](https://github.com/dedis/kyber) project from the DEDIS research lab.

One noteworthy implemenation detail was unifying the implementations of the LibP2P Edwards25519 Elliptic Curve library, with the Kyber Edwards25519 one. Due to slight differences in their respective approaches, special care needed to be taken to keep the LipP2P Peer ID system, while still using the Kyber Scalars and Points for the low level DKG operations.

The `dkg/dkg.go` file is the main operations regarding building the DKG, like Deal generation, and response processing. The `dkg/protocol.go` file provides all the protocol interactions with peers for the DKG, like sharing deals, and broadcasting responses.

## Next Steps
This project was intended to re-implement the `dkg-experiment` repo with the LibP2P framework, and to successfully generate a DKG group. Next steps are to futher implement the Secrets Management Engine proxy re-encryption methods, without the policy document system, then again with it. 

More information regarding the Secrets Management Engine implementation and details can be found in its Overview document [here](https://docs.google.com/document/d/1avrCTzAdSjJwO2nyMJNGmbtoYnFYwur-nHpjuG9kCuA/edit).

## Author
 - @jsimnz, John-Alan Simmons, CTO Source