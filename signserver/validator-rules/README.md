# SignServer Validator rule catalog

This directory holds **all the knowledge** the SignServer Validator uses to
check:

1. **Worker configuration**: unknown properties, properties that belong to
   another worker type, invalid values, missing required properties and
   cross-property rules.
2. **signclient commands**: the command, option names, option values and
   option combinations.
3. **Command + worker**: whether the command fits the target worker. This
   covers worker kind, client-side hashing, request metadata overrides and
   authentication.

The Java engine (`modules/SignServer-Validator-Core`) is generic. To change
what is validated, edit the YAML files here. You don't need to touch Java.

```
catalog.yaml              index of every file + catalogVersion (bump it on every change)
value-types.yaml          reusable value types (boolean, digestAlgorithm, url, ...)
common/*.yaml             property groups inherited by workers (base-worker, base-signer, ...)
workers/*.yaml            one file per worker type
cli/*.yaml                one file per signclient command (+ shared option groups)
combinations.yaml         rules needing both a command and a worker configuration
tests/*.yaml              golden test cases (the regression suite of the catalog)
schema/catalog.schema.json  JSON Schema of every file type (editor + CI validation)
MAINTAINING.md            how to update the catalog, by hand or with AI
```

## Running the validator

```bash
# Against a running SignServer (REST API, needs an admin client certificate)
bin/signserver-validator validate --worker CMSSigner \
    --keystore admin.p12 --truststore truststore.jks \
    --cli "signclient signdocument -workername CMSSigner -infile a.txt -outfile a.p7s"

# Offline, from a properties file (setproperties / dumpproperties format)
bin/signserver-validator validate --config-file doc/sample-configs/cmssigner.properties

# Only a command
bin/signserver-validator validate --cli "signclient signdocument -workername X -data hi" --format text

# Check the catalog itself
bin/signserver-validator selftest     # golden tests
bin/signserver-validator drift        # catalog vs. source code
```

The output is JSON by default (`--format text` for people). The exit code is
0 when validation passed, 1 when it failed and 2 on a usage or connection
error. `--strict` makes warnings fail too.

`bin/signserver-validator` reads this directory directly, so a change here
takes effect immediately. Without the directory, the copy embedded in the jar
at build time is used. `--rules <dir>` selects another catalog.

## Finding codes

| Code | Severity | Meaning |
|---|---|---|
| `PROP_WRONG_WORKER` | ERROR | Property belongs to another worker type (e.g. a PDFSigner property on a CMSSigner) |
| `PROP_UNKNOWN` | WARNING | Property not known for this worker; it will be ignored ("did you mean" hint) |
| `PROP_NOT_APPLICABLE` | WARNING | Property only applies under a condition that is not met (e.g. keystore properties without KeystoreCryptoToken) |
| `PROP_MISSING` | ERROR | Required property not set |
| `PROP_DEPRECATED` | WARNING | Deprecated property |
| `VALUE_INVALID` | ERROR (or the property's `invalidSeverity`) | Value does not match the property type |
| `WORKER_TYPE_UNKNOWN` | WARNING | No worker file for this IMPLEMENTATION_CLASS; only common properties are checked |
| `CLI_UNKNOWN_COMMAND`, `CLI_UNKNOWN_OPTION`, `CLI_MISSING_ARGUMENT`, `CLI_VALUE_INVALID` | ERROR | Command line problems |
| `CLI_DUPLICATE_OPTION`, `CLI_UNEXPECTED_ARGUMENT` | WARNING | Command line oddities |
| `COMBO_WRONG_WORKER_KIND` | ERROR | Command can not be used with this kind of worker |
| `COMBO_TARGET_MISMATCH` | WARNING | `-workername`/`-workerid` is not the validated worker |
| `META_UNKNOWN` | WARNING | `-metadata` key the worker does not use |
| `META_OVERRIDE_NOT_ALLOWED` | ERROR | `-metadata` override the worker configuration does not permit |
| `META_VALUE_INVALID` | ERROR | Invalid `-metadata` value |
| `RULE_<id>` | as declared | A catalog rule fired |
| `NOT_VERIFIED` | INFO | A rule needed information that was not available (e.g. other workers when validating one file) |

`passed` is true when there are no ERROR findings (with `--strict`, no
WARNING findings either).

## File formats

The JSON Schema (`schema/catalog.schema.json`) is the authoritative reference.
Editors with the YAML language server use it automatically through the first
line of each file. The engine also rejects unknown keys, unknown types,
groups or predicates, duplicate rule IDs, and defaults that are invalid for
their own type. It reports every problem at once.

### Properties

```yaml
properties:
  DETACHEDSIGNATURE:
    type: boolean              # a type from value-types.yaml or the file's own "types:"
    default: "FALSE"           # used by rules when the property is not set
    required: false
    allowedValues: [A, B]      # optional extra restriction
    caseSensitive: true        # for allowedValues (default: case-insensitive)
    invalidSeverity: WARNING   # severity of VALUE_INVALID (default ERROR)
    sensitive: true            # never show the value in reports
    deprecated: "message"      # report PROP_DEPRECATED
    source: "CMSSigner.DETACHEDSIGNATURE_PROPERTY"   # where in the code (provenance)
    doc: "doc/htdocs/CMS_Signer.html"
propertyPatterns:              # names built at runtime
  - { pattern: "USER\\..+", type: string, sensitive: true }
```

Empty values count as "not set", the same as `WorkerConfig.getProperty`.
Values exported as `_MASKED_` are not type-checked.

### Workers and groups

A worker file is selected when every `match` entry equals the configuration.
When several files match, the one with the most entries wins. A worker gets
the properties and rules of its `inherits` groups (in order), then of any
`conditionalInherits` whose `when` holds, then its own. For example,
`base-processable` adds `keystore-crypto-token` when
`CRYPTOTOKEN_IMPLEMENTATION_CLASS` is KeystoreCryptoToken.

A property that is not declared for the worker is reported as one of:

- `PROP_NOT_APPLICABLE`, if one of the worker's conditional groups declares it;
- `PROP_WRONG_WORKER`, if another worker type declares it;
- `PROP_UNKNOWN`, otherwise.

`kind` (`signer`, `crypto`, `validator`, `timestamp`, `sod`, `other`) is
matched against a command's `targetKinds`. `capabilities` are free-form tags
used by rules (`worker.hasCapability`). `requestMetadata` lists the
`-metadata` keys the worker accepts. `requiresTrue: P` means the override
needs `P=TRUE`; `requiresListed: P` means the key must be in the
comma-separated list `P`.

### Rules

```yaml
rules:
  - id: CSH-1                      # unique; the finding code is RULE_CSH-1
    when: { anyTrue: [CLIENTSIDEHASHING, ALLOW_CLIENTSIDEHASHING_OVERRIDE] }
    require: { present: ACCEPTED_HASH_DIGEST_ALGORITHMS }
    severity: ERROR
    property: ACCEPTED_HASH_DIGEST_ALGORITHMS   # what the finding points at
    option: clientside                          # (for CLI/combination rules)
    message: "... ${PROPERTY} ... ${cli:option} ... ${worker} ..."
    suggestion: "how to fix"
    source: "where the rule comes from in the code"
```

A finding is produced when `when` holds (or is missing) and `require` does
not hold (or is missing, which makes it a notice). Rules in worker and group
files are evaluated against the configuration, rules in `cli/` files against
the command, and `combinations.yaml` (and `combinationRules:`) against both.

**Predicates** (a closed set; each one is an object with a single key):

| Predicate | True when |
|---|---|
| `present: P` / `absent: P` | P is set / not set (non-blank) |
| `presentMatching: regex` | some property whose name matches is set |
| `isTrue: P` / `isFalse: P` | effective value of P (configured, else default) is TRUE / FALSE |
| `anyTrue: [P..]` / `allTrue: [P..]` | any / all are TRUE |
| `equals: {P: v}` / `in: {P: [v..]}` / `matches: {P: regex}` | comparison of the effective value (case-insensitive) |
| `listExcludes: {property: P, values: [..]}` | comma list P contains none of the values |
| `all: [..]` / `any: [..]` / `not: {..}` / `exactlyOne: [..]` / `atMostOne: [..]` | logic |
| `cli.command: name` | the command is `name` (or one of a list) |
| `cli.hasOption: o` | option `-o` is given |
| `cli.optionEquals: {o: v}` / `cli.optionIn: {o: [..]}` / `cli.optionMatches: {o: regex}` | option value, or its default (case-sensitive) |
| `cli.optionValueInList: {option, property, normalize: digest}` | option value is in the comma list property |
| `worker.kind: k` / `worker.is: Name` / `worker.hasCapability: c` / `worker.known: true` | about the worker type |
| `directory.workerExists: P` / `directory.workerKind: {property: P, kind: crypto}` | P names an existing worker (of that kind) |
| `custom: {check: id, ...}` | Java `CustomPredicate` registered with ServiceLoader (escape hatch) |

Evaluation uses three values. When a predicate needs data that is not
available (no command, an unknown worker type, other workers not known
offline), the result is *unknown*, and ERROR/WARNING rules then produce an
INFO `NOT_VERIFIED` finding instead of a false alarm.

### CLI commands

```yaml
command: signdocument
targetKinds: [signer]           # COMBO_WRONG_WORKER_KIND otherwise
workerOptions: [workername, workerid]
optionGroups: [keystore-options]
options:
  protocol: { arg: true, type: string, allowedValues: [HTTP, REST], caseSensitive: true, default: HTTP }
  metadata: { arg: true, repeatable: true, type: keyValue }
  clientside: { arg: false }
```

### Golden tests

```yaml
tests:
  - name: unique-name
    extends: other-test          # inherit config / otherWorkers / cli
    config: { NAME: X, ... }     # quote values: "TRUE", "1"
    otherWorkers: [ {...} ]      # makes cross-worker rules verifiable
    cli: "signclient signdocument ..."
    expectPassed: false
    expectCodes: ["PROP_WRONG_WORKER:VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH", "RULE_CSH-1"]
    forbidCodes: [PROP_UNKNOWN]
```

`CODE:X` matches a finding with that code whose property or option is X.

## Where this is going

- **v1 (now):** standalone `bin/signserver-validator` next to WildFly, using
  REST or a properties file.
- **Admin Web:** a "Validate" button under the properties table in
  `worker-configuration.xhtml`, calling `SignServerValidator` from
  `AdminWebSessionBean` with the local worker session (no REST). The core
  module has no server dependencies, so it can be embedded as is.
- **As a worker:** a `ValidatorWorker` (JSON in, JSON out) built with the
  same core. It exposes other workers' configuration, so restrict its
  `AUTHTYPE` to administrators.
