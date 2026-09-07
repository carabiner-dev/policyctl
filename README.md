# policyctl

`policyctl` is the command line tool to author, inspect, sign, test and
document [AMPEL](https://github.com/carabiner-dev/ampel) policy materials:
policies, policy sets and policy groups.

## Installing

```console
go install github.com/carabiner-dev/policyctl@latest
```

## Commands

| Command | Purpose |
|---------|---------|
| `create` | Create skeleton policies and policy sets |
| `parse` | Parse a policy file and report problems |
| `compile` | Compile a policy or policy set, resolving remote references, into a standalone file |
| `check-update` / `update` | Check policy references for newer versions, and update them |
| `sign` / `verify` | Sign a policy or policy set, and verify a signed one |
| `keys` | Tools to work with signing keys |
| `test` | Run policy tests from a `.ptests.yaml` file |
| `doc` | Generate documentation for a policy, set or group |
| `doc index` | Generate an index of policy materials |

Run `policyctl <command> --help` for the flags of each command.

## Generating documentation

`policyctl doc` reads a policy, policy set or policy group (JSON or HJSON),
compiles it, and writes a document describing it: an overview table, the
context values and identities it declares, its tenets with their evaluation
code and messages, and a diagram of its structure.

```console
policyctl doc slsa/slsa-build-point.hjson             # rendered in the terminal
policyctl doc -o slsa/slsa-build-point.md slsa/slsa-build-point.hjson
policyctl doc -f html -o build-point.html slsa/slsa-build-point.hjson
```

The format is `terminal` by default and is inferred from the output file
extension (`.html` or `.htm` for HTML, markdown otherwise); `--format` sets it
explicitly. A policy that declares a `name` in its metadata is titled by
that name, with its ID shown in the overview table.

### Diagrams

Every document embeds a [mermaid](https://mermaid.js.org/) diagram under its
*Structure* section, rendered inline by viewers that support mermaid and by
the HTML output.

- A **policy** diagram shows its inputs, the attestation (predicate) types
  it consumes, the context values it takes with their type, required flag
  and default, and any evidence chain links, followed by its tenets. When a
  policy has several tenets, a decision node states how they combine: *ALL
  tenets must pass* under `AND` (the default) or *ANY tenet passing
  suffices* under `OR`.
- A **policy group** diagram shows its blocks and the policies each block
  offers as alternatives, with the assert mode combining the blocks and, for
  blocks with several policies, the mode combining those.
- A **policy set** diagram shows its policies with their tenets, and its
  groups with their blocks.

Two flags control the diagrams:

| Flag | Default | Effect |
|------|---------|--------|
| `--diagram` | `true` | Embed diagrams. `--diagram=false` omits every diagram. |
| `--policy-details` | `false` | Also add each embedded policy's own diagram to set and group documents. |

Diagrams are rendered through the `Diagrammer` interface of the
`pkg/doc` package, so other diagram languages can be added without touching
the document generator.

### Indexes

`policyctl doc index` writes an index of the policy materials given on the
command line, meant to sit as the `README.md` of a directory of policies:

```console
policyctl doc index -o slsa/README.md slsa/*.hjson
policyctl doc index -f html -o index.html slsa/*.hjson groups/*/*.hjson
```

The index has a section per kind of material, each a table:

| Section | Columns |
|---------|---------|
| Policies | ID, name, predicate types the policy consumes (one per line) |
| Policy sets | ID, number of policies, number of groups, predicate types consumed by everything in the set |
| Policy groups | ID, number of blocks, number of policies across the blocks, predicate types consumed by the policies in the group |

Sections without entries are omitted. Each ID links to the material's own
document, expected next to its source file with the `.md` extension, which is
what `policyctl doc -o` produces when given the same base name. Links are
relative to the index location.

Each table sits between marker comments:

```markdown
<!-- policyctl:index:policies:begin -->
| ID | Name | Predicate types |
...
<!-- policyctl:index:policies:end -->
```

When the markdown output file already exists, only the text between the
markers is replaced and everything else is kept. This lets a directory
README carry its own title, an introduction and text within each section
that survive regeneration. A section that gains entries but has no markers
yet is appended at the end. `--title` names a newly created index (default
*Policy index*). HTML output is always rendered from scratch.

## License

Apache-2.0. See [LICENSE](./LICENSE).
