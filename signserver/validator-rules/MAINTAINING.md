# Maintaining the rule catalog (by hand or with AI)

The catalog is designed so that changes are **small, reviewable and checked
by machines**:

- the engine loads it strictly and reports every structural problem;
- the JSON Schema validates every file (in editors and in the unit tests);
- the golden tests (`tests/*.yaml`) pin the expected behaviour;
- the **drift check** compares the catalog with the SignServer sources.

## The loop

```bash
# 1. What changed in the code? (lists names missing from the catalog, and stale ones)
bin/signserver-validator drift --signserver-home . --format text

# 2. Edit the YAML files (see README.md), add golden tests for the new rules,
#    bump catalogVersion in catalog.yaml

# 3. Check without building
bin/signserver-validator selftest

# 4. Full check (schema + golden tests + drift + engine tests)
mvn -pl modules/SignServer-Validator-Core,modules/SignServer-Validator-CLI install
```

## Adding a worker type

1. Create `workers/<Name>.yaml` with `worker`, `kind`, `match`
   (IMPLEMENTATION_CLASS and, for crypto workers, CRYPTOTOKEN_IMPLEMENTATION_CLASS),
   `inherits` and `extraction.sources` (the Java files with its constants).
2. Add it to `catalog.yaml`.
3. Run `drift`. Every name it reports as "in code, missing in catalog" must
   become a property. If it is not a worker property (a value constant, or a
   request metadata key), add it to `extraction.ignoreConstants` with a
   comment.
4. For each property, read how the worker's `init()` (or its parameters
   class) parses it, and choose `type`, `default`, `allowedValues` and
   `required`. Every check `init()` adds to `configErrors`/`fatalErrors`
   becomes a rule, with the code location in `source:`.
5. List the request metadata keys the worker reads (`RequestMetadata...get`,
   `requestMetadata.get`) under `requestMetadata`.
6. Add golden tests: one passing configuration (the matching file of
   `doc/sample-configs/` is a good start) and one failing case per rule.

## Using AI

You can hand the job to an AI assistant (e.g. Claude Code in this
repository) with a prompt like the one below. Its output then goes through
the same checks and a normal code review.

> Update the SignServer Validator rule catalog in `signserver/validator-rules`.
> Run `bin/signserver-validator drift --signserver-home . --format text` and
> fix all drift. For new worker types, follow "Adding a worker type" in
> `validator-rules/MAINTAINING.md`. Derive types, defaults, allowed values
> and rules only from the worker's source code (`init()`, the parameters
> class, `getFatalErrors`) and its page in `doc/htdocs/`. Record each one's
> origin in `source:`. Don't invent rules you can't point to in code or
> documentation. Add golden tests for every new rule, bump `catalogVersion`,
> then run `bin/signserver-validator selftest` and the Maven build of the
> validator modules until both pass.

Rules of thumb for reviewing AI-made (or any) changes:

- Every new rule has a `source:` that points at real code or documentation.
- Every new rule has at least one golden test that triggers it.
- No existing golden test was weakened or removed to make the build pass.
- A severity of ERROR means the server rejects the configuration or request,
  or ignores it in a way that breaks it. Use WARNING for "probably a mistake"
  and INFO for reminders.
