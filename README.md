# observation-primitive

The canonical substrate atom: observation as fundamental primitive.

Distilled from R10 reverse-engineering.

```rust
use observation_primitive::{Observation, fnv1a64_hex, int16_dials};

let o = Observation::new(
    "substrate",
    "has_primitive",
    serde_json::json!("observation"),
    "casey",
    None,
);
println!("{}", o.id);

// Fleet canary check
assert_eq!(fnv1a64_hex("café Δ 日本語"), "024a555471370b18d");
```

## Doctrines (R10 canonical)
- 3 forms of evidence: direct (FNV-1a hash), witness (other observations), pattern (JEPA detects fit)
- 3 kinds of forgetting: bundle (archive), traversal (scar), evidence (decay)
- 11 opcodes: 5 base (BIND/LINK/EFFECT/VIEW/TICK) + 6 proposed (ATTEST/DELEGATE/CONTEST/MERGE/REVOKE/WITHDRAW)

Inspired by [evintunador/context-graph](https://github.com/evintunador/context-graph)'s evidence-backed typed graph model: every observation carries the evidence that justifies it.
