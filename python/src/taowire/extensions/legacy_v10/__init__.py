"""Two-way legacy v10 bridge (spec 8.11). Opt-in and time-boxed.

- :mod:`.wire`: the v10 wire format, from captured vectors (8.11.1).
- :mod:`.server`: v10 Dendrites → a TaoWire miner (8.11.2).
- :mod:`.client`: a TaoWire validator → v10 Axons (8.11.3).

Nothing here imports bittensor v10 (ADR-0008).
"""
