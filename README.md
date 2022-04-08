New bitcoin node implementation from sratch in Rust with minimal dependencies.

Project started Jan 16 2022.

## WHAT IT DOES SO FAR:
- handshake with nodes on the network
- store mempool transactions
- request headers and blocks
- perform IBD
- construct, parse, and execute tx scripts (verify sigs)
- verify difficulty target in headers
- track & maintain UTXO set
- verify all tx inputs against UTXOs
- verify coinbase issuance is correct (halvening)
- saves all necessary data to disk (albeit in a clunky and slow manner)

## WHAT IT DOES NOT DO:
- various BIPs are unimplemented
- a few opcodes are unimplemented
- P2SH is unimplemented
- SegWit is unimplemented
- Taproot is unimplemented
- does not forward anything to peers (only downloads info)
- immediately panics if a peer sends invalid data
- does not track peer misbehavior

*This is summary is probably inaccurate and incomplete. Will be updated over time.*