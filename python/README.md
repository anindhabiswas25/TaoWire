# taowire (Python)

> **Alpha (0.1.0a1).** TaoWire has **not been security-reviewed** yet, and its APIs may change between
> alphas. Use it on localnet and testnet; **do not use it to protect mainnet value**. Feedback and bugs:
> [GitHub issues](https://github.com/anindhabiswas25/TaoWire/issues). Security problems: report them privately through
> [GitHub private vulnerability reporting](https://github.com/anindhabiswas25/TaoWire/security/advisories/new) (see
> [SECURITY.md](https://github.com/anindhabiswas25/TaoWire/blob/main/SECURITY.md)), never in a public issue.

The Python package of [TaoWire](https://github.com/anindhabiswas25/TaoWire): miner server, validator client, security layer, chain
gateway, compat layer for v10 subnets, test harness and CLI, for Bittensor v11 subnets
(`bittensor>=11.3,<12`, Python 3.10–3.14).

```bash
pip install "taowire[all]==0.1.0a1"     # a pre-release: plain `pip install taowire` skips it
taowire init my-subnet                  # a working example subnet to start from
```

Start with the [quickstart](https://github.com/anindhabiswas25/TaoWire/blob/main/docs/quickstart.md) (a subnet on a local chain, from
`taowire init` to weights on chain); the [documentation](https://github.com/anindhabiswas25/TaoWire/tree/main/docs) covers the miner, the
validator, security and migrating a v10 subnet. Extras: `redis` (shared replay store and rate limits),
`ntp` (clock guard), `migrate` (`taowire migrate`), `all`.

License: Apache-2.0.
