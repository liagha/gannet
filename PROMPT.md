Here is your full prompt to give to an AI. Copy and paste exactly this.

---

## PROMPT START

You are helping me build **Gannet** — a Rust networking tool for device discovery, fingerprinting, identity tracking, and authorized security testing on my own networks.

### PROJECT VISION

Gannet discovers devices on my network (whether I am the router or not), assigns persistent identities with human‑readable tags, and provides a clean interface for targeting specific devices. The tool will eventually include penetration testing modules for my own networks only.

The core unsolved problem is **identity resolution** — looking at multiple devices and knowing which one is my target (e.g., my friend Alice's laptop) without manual IP tracking.

### INCREMENTAL WRITING & STATUS SYSTEM

You must maintain a **STATUS.md** file at the project root. This file is the single source of truth for what exists, what is being worked on, and what comes next.

#### STATUS.md format:

```markdown
# GANNET STATUS

## PHASE: [Current Phase Name]

### COMPLETED MODULES
- [module name] - [brief what it does] - [file path]
- [module name] - [brief what it does] - [file path]

### IN PROGRESS
- [module name] - [what remains to finish] - [file path]

### NEXT UP
- [module name] - [why needed]

### KNOWN ISSUES / BLOCKERS
- [issue] - [blocked by what]

### SESSION NOTES
[Date YYYY-MM-DD]
- [what was done this session]
- [decisions made]
- [questions for next time]
```

#### Rules for STATUS.md:

1. Before any code change, you must read STATUS.md
2. After any code change, you must update STATUS.md to reflect the new state
3. Each session (conversation turn with code) starts with you stating: *"Reading STATUS.md... Current phase: X"*
4. Each session ends with you updating STATUS.md with session notes
5. If I provide no STATUS.md, you must create it from scratch based on our conversation history

### CODING RULES (NON‑NEGOTIABLE)

**No comments** — absolutely no inline, block, or docstring comments. Code must be entirely self‑explanatory.

**Naming:**
- Prefer single‑word names
- If unavoidable, use at most two words separated by underscore (snake_case)
- Names must be clear, concise, non‑acronym/shortened, and visually clean
- Avoid redundant context — if a variable or function is unique within its scope, use `left` instead of `left_type`

**Style inheritance:**
- If I provide existing code, mirror its style, structure, and naming scheme
- If provided code breaks these rules, fix it while keeping logical consistency
- Maintain uniform style across new and old code

**Structure over commentary** — Use language features, layout, and naming to convey meaning. Never need external explanation.

**Quality tone** — Code must read as clean, minimal, and deliberate — clarity through structure, not words.

### OUTPUT FORMAT RULES

**If no file changes:** State "No changes to [filename]" and explain why.

**If a file changes:** Rewrite the ENTIRE file in a single code snippet with a header comment identifying the file path and purpose (the header is the ONLY allowed comment):

```rust
// FILE: src/discovery/arp.rs
// PURPOSE: ARP scanning for device discovery on local subnet
[full file content]
```

**Never output partial diffs.** Always the complete file.

**If you need something from me** (a MAC OUI database, a config file format decision, etc.), state clearly: *"PROVIDE REQUIRED: [what you need]"* and wait.

### PROJECT STRUCTURE (to be built incrementally)

```
gannet/
├── STATUS.md
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── discovery/
│   │   ├── mod.rs
│   │   ├── arp.rs
│   │   ├── mdns.rs
│   │   └── fingerprint.rs
│   ├── identity/
│   │   ├── mod.rs
│   │   ├── device.rs
│   │   ├── store.rs
│   │   └── namer.rs
│   ├── cli/
│   │   ├── mod.rs
│   │   └── commands.rs
│   └── net/
│       ├── mod.rs
│       └── interface.rs
```

### IMMEDIATE TASKS

Start with Phase 1:

1. Create STATUS.md with initial state
2. Create Cargo.toml with dependencies: `pnet`, `tokio`, `serde`, `clap`, `macaddr`
3. Implement `src/discovery/arp.rs` — async ARP scanner that takes a subnet and returns list of responsive IPs with MAC addresses
4. Implement `src/main.rs` minimal CLI: `gannet scan` that prints discovered IPs and MACs

Do not implement anything beyond Phase 1 yet. After completing, update STATUS.md and wait for my next instruction.

### REMEMBER

- Read STATUS.md before every code change
- Update STATUS.md after every code change
- No comments in code
- Complete file rewrites only
- State "PROVIDE REQUIRED" if blocked
- Start each response with "Reading STATUS.md..."

---

## PROMPT END