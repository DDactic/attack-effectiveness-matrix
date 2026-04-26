# Contributing

Thanks for considering a contribution. The matrix is a community resource, and the only way it stays accurate is if researchers, blue teams, and vendors push back when a rating is wrong.

The most useful contributions, in rough order of value:

1. **New CVE-backed vectors.** A vector tied to a public CVE with a clear mechanism description, a `patched_since` date, and prerequisite conditions.
2. **Rating corrections.** A cell that you have empirically tested at a stated config level and that disagrees with the published rating.
3. **Modifier additions.** New technique or strategy modifiers that materially change effectiveness in a way the existing modifiers do not capture.
4. **Mechanism clarifications.** Edits to the `mechanism` field that make the attack more precise without changing the rating.
5. **Tooling.** Improvements to `scripts/sanitize.py` or new validators that catch schema regressions.

## How to propose a change

Open a pull request against `main`. Please follow the structure below.

### For a new vector

Add an entry to `data/attack_effectiveness_matrix.json` under `vectors`. Required fields:

- `name` (human-readable)
- `layer` (`l3` | `l4` | `l7` | `protocol`)
- `category` (existing category if it fits, new one if it doesn't)
- `mechanism` (one or two sentences explaining how the attack exhausts a resource)
- `effectiveness` (six architecture entries; each with `default` / `tuned` / `hardened` ratings and a one-line `notes`)
- `taxonomy_id` (e.g. `L7-42`; pick the next free id in the layer)

Strongly recommended:

- `prerequisites` (array of conditions that must be true)
- `cve_id` and `patched_since` if applicable
- `common_tools` with `script_kiddie` / `intermediate` / `advanced` tiers, listing **public** tools only
- `amp_factor` for amplification vectors

### For a rating revision

In your PR description, please include:

- The architecture and config level being revised.
- The evidence: a brief description of how you tested, what you observed, and what conditions were in place.
- The proposed new rating and the one-line `notes` that explains why.

We do not require raw packet captures or screenshots, but a reproducible setup is appreciated. Anonymized targets are fine.

### For a modifier change

Modifiers are by far the highest-leverage cells in the matrix because they multiply across all 213 vectors. Treat them with extra care. A modifier PR should include:

- The modifier name, family, mechanism, and per-architecture shifts.
- A worked example showing how the modifier moves at least three different vectors.
- A statement of which existing modifier (if any) it overlaps with and why a new modifier is justified.

## What we will reject

- Vendor-specific bypass recipes. The matrix is a vendor-neutral architectural reference; per-vendor playbooks belong in vendor advisories or NDA-bound engagements.
- Ratings without a stated methodology. "We tried it once and it worked" is not enough; we need to know what `default`/`tuned`/`hardened` actually meant in your setup.
- Tooling references that point at a tool we cannot find or evaluate. Open-source preferred; commercial fine if there is a published spec.
- Anything that looks like an instruction set ("send these exact bytes to bypass X"). Mechanism descriptions stay at the level of *what* is exhausted and *why*, not byte-level payloads.

## Code style

- Python 3.10+, type hints encouraged.
- JSON formatted with 2-space indent. Run `python -m json.tool data/attack_effectiveness_matrix.json --indent 2 | sponge data/attack_effectiveness_matrix.json` before committing.
- Keep the file deterministic: keys in the order they currently appear, no trailing whitespace, single trailing newline.

## CLA

There is no CLA. By submitting a PR you agree that your contribution is licensed under the same terms as the repository: CC-BY-4.0 for the data, MIT for code.

## Issues vs PRs

If you are not sure whether a change makes sense, open an issue first. If you have already made the change locally, send the PR; we would rather review code than chase a discussion thread.

## Maintainers

DDactic security research team. Reach us via the email in [CITATION.cff](CITATION.cff) or by opening an issue.
