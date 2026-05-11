// FILE: src/identity/namer.rs
// PURPOSE: Deterministic human-readable tag generation seeded by device key
const ADJECTIVES: &[&str] = &[
    "amber", "azure", "bold", "brisk", "calm", "cedar", "clear", "coral",
    "crisp", "dusk", "ember", "fleet", "frost", "gold", "grave", "iron",
    "jade", "keen", "lark", "lunar", "mesa", "mild", "misty", "noble",
    "opal", "pale", "pine", "quiet", "rapid", "raven", "rigid", "rocky",
    "sage", "salt", "sharp", "silk", "slate", "solar", "stark", "steel",
    "still", "stone", "storm", "stout", "swift", "tidal", "tawny", "thorn",
    "vale", "vivid", "warm", "wild", "wry", "zeal",
];

const NOUNS: &[&str] = &[
    "anchor", "anvil", "arch", "arrow", "axle", "basin", "beam", "bell",
    "blade", "bloom", "bolt", "bough", "brook", "cape", "chain", "cliff",
    "coil", "crest", "crown", "delta", "dome", "draft", "drift", "drum",
    "dune", "fern", "field", "flare", "flint", "forge", "gale", "gate",
    "gear", "glen", "grove", "helm", "hull", "keel", "knoll", "lance",
    "ledge", "loom", "mast", "mill", "moor", "notch", "orbit", "peak",
    "pike", "plume", "pond", "quill", "rail", "reef", "ridge", "rivet",
    "rook", "root", "rudder", "rune", "shaft", "shore", "silt", "slab",
    "spar", "spike", "spire", "spool", "sprig", "squad", "stave", "stem",
    "step", "tide", "torch", "trace", "trail", "twig", "vale", "vault",
    "veil", "vent", "wake", "wall", "wave", "wedge", "well", "wire",
];

fn hash_key(key: &str) -> u64 {
    key.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        h.wrapping_mul(0x100000001b3).wrapping_add(b as u64)
    })
}

pub fn generate(key: &str) -> String {
    let h = hash_key(key);
    let adj = ADJECTIVES[(h as usize) % ADJECTIVES.len()];
    let noun = NOUNS[((h >> 32) as usize) % NOUNS.len()];
    format!("{}-{}", adj, noun)
}