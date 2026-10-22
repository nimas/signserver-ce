package org.signserver.validator.catalog;

/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.signserver.validator.catalog.CatalogModel.CliFile;
import org.signserver.validator.catalog.CatalogModel.CliOptionGroupFile;
import org.signserver.validator.catalog.CatalogModel.CombinationsFile;
import org.signserver.validator.catalog.CatalogModel.ConditionalInherit;
import org.signserver.validator.catalog.CatalogModel.GoldenTest;
import org.signserver.validator.catalog.CatalogModel.GroupFile;
import org.signserver.validator.catalog.CatalogModel.IndexFile;
import org.signserver.validator.catalog.CatalogModel.MetadataKeySpec;
import org.signserver.validator.catalog.CatalogModel.OptionSpec;
import org.signserver.validator.catalog.CatalogModel.PatternSpec;
import org.signserver.validator.catalog.CatalogModel.PropertySpec;
import org.signserver.validator.catalog.CatalogModel.RequestMetadataSpec;
import org.signserver.validator.catalog.CatalogModel.RuleSpec;
import org.signserver.validator.catalog.CatalogModel.TestFile;
import org.signserver.validator.catalog.CatalogModel.TypeDef;
import org.signserver.validator.catalog.CatalogModel.ValueTypesFile;
import org.signserver.validator.catalog.CatalogModel.WorkerFile;
import org.signserver.validator.catalog.ResolvedWorker.SourcedMetadataKey;
import org.signserver.validator.catalog.ResolvedWorker.SourcedPattern;
import org.signserver.validator.catalog.ResolvedWorker.SourcedProperty;
import org.signserver.validator.catalog.ResolvedWorker.SourcedRule;
import org.signserver.validator.eval.EvalContext;
import org.signserver.validator.eval.PredicateEvaluator;
import org.signserver.validator.eval.Tri;
import org.signserver.validator.eval.ValueTypeRegistry;

/**
 * The loaded and cross-checked rule catalog.
 *
 * @version $Id$
 */
public final class RuleCatalog {

    /** The group every worker gets when no worker file matches. */
    public static final String FALLBACK_GROUP = "base-worker";

    private static final Set<String> KINDS = Set.of("signer", "crypto",
            "validator", "timestamp", "sod", "other");
    private static final Set<String> SEVERITIES = Set.of("ERROR", "WARNING", "INFO");

    /** A golden test together with the catalog file declaring it. */
    public record SourcedTest(GoldenTest test, String file) {
    }

    private final String catalogVersion;
    private final String sourceDescription;
    private final ValueTypeRegistry types;
    private final Map<String, GroupFile> groups;
    private final Map<String, String> groupFiles;
    private final Map<String, WorkerFile> workers;
    private final Map<String, String> workerFiles;
    private final Map<String, ResolvedCommand> commands;
    private final List<SourcedRule> combinationRules;
    private final List<SourcedTest> tests;
    private final Map<String, CliOptionGroupFile> optionGroups;
    private final Map<String, String> optionGroupFiles;
    private final Map<String, CliFile> cliFiles;

    private RuleCatalog(final Builder b) {
        this.catalogVersion = b.index.catalogVersion();
        this.sourceDescription = b.source.describe();
        this.types = b.registry;
        this.groups = b.groups;
        this.groupFiles = b.groupFiles;
        this.workers = b.workers;
        this.workerFiles = b.workerFiles;
        this.commands = b.commands;
        this.combinationRules = b.combinationRules;
        this.tests = b.tests;
        this.optionGroups = b.optionGroups;
        this.optionGroupFiles = b.optionGroupFiles;
        this.cliFiles = b.cliFiles;
    }

    /**
     * Loads and checks the catalog.
     *
     * @param source where to read the files from
     * @return the catalog
     * @throws CatalogException listing every problem found
     */
    public static RuleCatalog load(final CatalogSource source) throws CatalogException {
        final Builder b = new Builder(source);
        b.read();
        if (!b.problems.isEmpty()) {
            throw new CatalogException(b.problems);
        }
        final RuleCatalog catalog = new RuleCatalog(b);
        final List<String> problems = catalog.crossCheck();
        if (!problems.isEmpty()) {
            throw new CatalogException(problems);
        }
        return catalog;
    }

    public String getCatalogVersion() {
        return catalogVersion;
    }

    public String getSourceDescription() {
        return sourceDescription;
    }

    public ValueTypeRegistry getTypes() {
        return types;
    }

    public Map<String, WorkerFile> getWorkers() {
        return Collections.unmodifiableMap(workers);
    }

    public String getWorkerFile(final String workerName) {
        return workerFiles.get(workerName);
    }

    public Map<String, ResolvedCommand> getCommands() {
        return Collections.unmodifiableMap(commands);
    }

    public Map<String, CliOptionGroupFile> getOptionGroups() {
        return Collections.unmodifiableMap(optionGroups);
    }

    public String getOptionGroupFile(final String name) {
        return optionGroupFiles.get(name);
    }

    /**
     * @param file catalog file of a command
     * @return the extraction section of the command file, or null
     */
    public CatalogModel.ExtractionSpec getCliExtraction(final String file) {
        final CliFile c = cliFiles.get(file);
        return c == null ? null : c.extraction();
    }

    public List<SourcedRule> getCombinationRules() {
        return combinationRules;
    }

    public List<SourcedTest> getTests() {
        return tests;
    }

    /**
     * Finds the worker file matching a configuration. When several match, the
     * one with the most match conditions wins.
     *
     * @param config configuration with upper-case keys
     * @return the worker file or empty when the worker type is not in the catalog
     */
    public Optional<WorkerFile> findWorker(final Map<String, String> config) {
        WorkerFile best = null;
        for (WorkerFile w : workers.values()) {
            final boolean matches = w.match().entrySet().stream().allMatch(e -> {
                final String v = config.get(e.getKey().toUpperCase());
                return v != null && v.trim().equals(e.getValue());
            });
            if (matches && (best == null || w.match().size() > best.match().size())) {
                best = w;
            }
        }
        return Optional.ofNullable(best);
    }

    /**
     * @param config configuration with upper-case keys
     * @return the worker kind: from the matching worker file, else derived
     * from TYPE (CRYPTO_WORKER means crypto), else null
     */
    public String kindOf(final Map<String, String> config) {
        final Optional<WorkerFile> w = findWorker(config);
        if (w.isPresent()) {
            return w.get().kind();
        }
        final String type = config.get("TYPE");
        return type != null && type.trim().equals("CRYPTO_WORKER") ? "crypto" : null;
    }

    /**
     * Resolves what the catalog says about a configuration.
     *
     * @param config configuration with upper-case keys
     * @return the resolved worker; for unknown worker types only the
     * fallback group is applied and isKnown() is false
     */
    public ResolvedWorker resolve(final Map<String, String> config) {
        final Optional<WorkerFile> wf = findWorker(config);
        final Resolution r = new Resolution(config);
        if (wf.isEmpty()) {
            r.addGroup(FALLBACK_GROUP);
            final String impl = config.get("IMPLEMENTATION_CLASS");
            final String name = impl == null ? "unknown worker"
                    : impl.substring(impl.lastIndexOf('.') + 1).trim();
            return r.build(name, kindOf(config), false, null);
        }
        final WorkerFile w = wf.get();
        final String file = workerFiles.get(w.worker());
        for (String g : nullSafe(w.inherits())) {
            r.addGroup(g);
        }
        r.addConditional(w.conditionalInherits());
        r.addContent(file, w.properties(), w.propertyPatterns(), w.rules(),
                w.combinationRules(), w.requestMetadata());
        r.capabilities.addAll(nullSafe(w.capabilities()));
        return r.build(w.worker(), w.kind(), true, file);
    }

    /**
     * @param propertyName upper-case property name
     * @return names of the catalog workers that declare the property
     * unconditionally
     */
    public Set<String> ownersOf(final String propertyName) {
        final Set<String> owners = new TreeSet<>();
        for (WorkerFile w : workers.values()) {
            if (closure(w, false).contains(propertyName) || matchesPattern(w, false, propertyName)) {
                owners.add(w.worker());
            }
        }
        return owners;
    }

    /**
     * @param workerName catalog worker name
     * @param propertyName upper-case property name
     * @return the conditions under which a conditional group of the worker
     * declares the property (empty if none does)
     */
    public List<JsonNode> conditionsDeclaring(final String workerName, final String propertyName) {
        final WorkerFile w = workers.get(workerName);
        final List<JsonNode> result = new ArrayList<>();
        if (w == null) {
            return result;
        }
        final List<ConditionalInherit> all = new ArrayList<>(nullSafe(w.conditionalInherits()));
        for (String g : groupClosure(nullSafe(w.inherits()), false)) {
            all.addAll(nullSafe(groups.get(g).conditionalInherits()));
        }
        for (ConditionalInherit ci : all) {
            for (String g : groupClosure(ci.groups(), true)) {
                final GroupFile gf = groups.get(g);
                if ((gf.properties() != null && gf.properties().containsKey(propertyName))
                        || nullSafe(gf.propertyPatterns()).stream().anyMatch(p -> p.pattern() != null
                        && Pattern.matches(p.pattern(), propertyName))) {
                    result.add(ci.when());
                }
            }
        }
        return result;
    }

    /** @return all property names any worker or group declares, for suggestions */
    public Set<String> allPropertyNames() {
        final Set<String> names = new TreeSet<>();
        groups.values().forEach(g -> names.addAll(nullSafeMap(g.properties()).keySet()));
        workers.values().forEach(w -> names.addAll(nullSafeMap(w.properties()).keySet()));
        return names;
    }

    /**
     * @param worker catalog worker
     * @param includeConditional whether to include conditional groups
     * @return property names the worker declares
     */
    public Set<String> closure(final WorkerFile worker, final boolean includeConditional) {
        final Set<String> names = new HashSet<>(nullSafeMap(worker.properties()).keySet());
        final List<String> roots = new ArrayList<>(nullSafe(worker.inherits()));
        if (includeConditional) {
            nullSafe(worker.conditionalInherits()).forEach(ci -> roots.addAll(ci.groups()));
        }
        for (String g : groupClosure(roots, includeConditional)) {
            names.addAll(nullSafeMap(groups.get(g).properties()).keySet());
        }
        return names;
    }

    private boolean matchesPattern(final WorkerFile worker, final boolean includeConditional,
            final String propertyName) {
        final List<PatternSpec> patterns = new ArrayList<>(nullSafe(worker.propertyPatterns()));
        for (String g : groupClosure(nullSafe(worker.inherits()), includeConditional)) {
            patterns.addAll(nullSafe(groups.get(g).propertyPatterns()));
        }
        return patterns.stream().anyMatch(p -> Pattern.matches(p.pattern(), propertyName));
    }

    /** Groups reachable from roots (optionally through conditional inherits). */
    private Set<String> groupClosure(final List<String> roots, final boolean includeConditional) {
        final Set<String> seen = new LinkedHashSet<>();
        final List<String> todo = new ArrayList<>(roots);
        while (!todo.isEmpty()) {
            final String g = todo.remove(0);
            if (!groups.containsKey(g) || !seen.add(g)) {
                continue;
            }
            if (includeConditional) {
                nullSafe(groups.get(g).conditionalInherits()).forEach(ci -> todo.addAll(ci.groups()));
            }
        }
        return seen;
    }

    /** Collects the content of the groups and the worker for one configuration. */
    private final class Resolution {
        private final Map<String, String> config;
        private final Set<String> visited = new HashSet<>();
        private final Map<String, SourcedProperty> properties = new LinkedHashMap<>();
        private final List<SourcedPattern> patterns = new ArrayList<>();
        private final List<SourcedRule> rules = new ArrayList<>();
        private final List<SourcedRule> comboRules = new ArrayList<>();
        private final Map<String, SourcedMetadataKey> metadata = new LinkedHashMap<>();
        private final Set<String> capabilities = new LinkedHashSet<>();
        private Boolean allowUnknownMetadata;

        Resolution(final Map<String, String> config) {
            this.config = config;
        }

        void addGroup(final String name) {
            if (!visited.add(name)) {
                return;
            }
            final GroupFile g = groups.get(name);
            addContent(groupFiles.get(name), g.properties(), g.propertyPatterns(), g.rules(),
                    g.combinationRules(), g.requestMetadata());
            addConditional(g.conditionalInherits());
        }

        void addConditional(final List<ConditionalInherit> conditionals) {
            for (ConditionalInherit ci : nullSafe(conditionals)) {
                final EvalContext ctx = new EvalContext(config, null, null, null, RuleCatalog.this);
                if (PredicateEvaluator.evaluate(ci.when(), ctx) == Tri.TRUE) {
                    ci.groups().forEach(this::addGroup);
                }
            }
        }

        void addContent(final String file, final Map<String, PropertySpec> props,
                final List<PatternSpec> pats, final List<RuleSpec> rs,
                final List<RuleSpec> combos, final RequestMetadataSpec md) {
            nullSafeMap(props).forEach((k, v) -> properties.put(k, new SourcedProperty(k, v, file)));
            nullSafe(pats).forEach(p -> patterns.add(new SourcedPattern(Pattern.compile(p.pattern()), p, file)));
            nullSafe(rs).forEach(r -> rules.add(new SourcedRule(r, file)));
            nullSafe(combos).forEach(r -> comboRules.add(new SourcedRule(r, file)));
            if (md != null) {
                nullSafeMap(md.keys()).forEach((k, v) -> metadata.put(k, new SourcedMetadataKey(k, v, file)));
                if (md.allowUnknown() != null) {
                    allowUnknownMetadata = md.allowUnknown();
                }
            }
        }

        ResolvedWorker build(final String name, final String kind, final boolean known, final String file) {
            return new ResolvedWorker(name, kind, known, file, capabilities, properties,
                    patterns, rules, comboRules, metadata,
                    allowUnknownMetadata == null || allowUnknownMetadata);
        }
    }

    /** Semantic checks that need the whole catalog. */
    private List<String> crossCheck() {
        final List<String> problems = new ArrayList<>(types.validateDefinitions());
        final Set<String> ruleIds = new HashSet<>();
        final java.util.function.BiConsumer<String, List<RuleSpec>> checkRules = (file, rules) -> {
            for (RuleSpec r : nullSafe(rules)) {
                final String where = file + " rule " + r.id();
                if (!ruleIds.add(r.id())) {
                    problems.add(where + ": duplicate rule id");
                }
                if (r.severity() == null || !SEVERITIES.contains(r.severity())) {
                    problems.add(where + ": severity must be ERROR, WARNING or INFO");
                }
                if (r.message() == null) {
                    problems.add(where + ": missing message");
                }
                if (r.when() == null && r.require() == null) {
                    problems.add(where + ": needs 'when' and/or 'require'");
                }
                if (r.when() != null) {
                    PredicateEvaluator.validate(r.when(), where + " when", problems);
                }
                if (r.require() != null) {
                    PredicateEvaluator.validate(r.require(), where + " require", problems);
                }
            }
        };
        final java.util.function.BiConsumer<String, Map<String, PropertySpec>> checkProps = (file, props) ->
            nullSafeMap(props).forEach((name, p) -> {
                if (!name.equals(name.toUpperCase())) {
                    problems.add(file + " property " + name + ": property names must be upper case");
                }
                if (p.type() != null && !types.has(p.type())) {
                    problems.add(file + " property " + name + ": unknown type '" + p.type() + "'");
                }
                if (p.invalidSeverity() != null && !SEVERITIES.contains(p.invalidSeverity())) {
                    problems.add(file + " property " + name + ": invalidSeverity must be ERROR, WARNING or INFO");
                }
                if (p.defaultValue() != null && !p.defaultValue().isBlank()
                        && types.check(p.type(), p.allowedValues(), p.caseSensitive(),
                                p.min(), p.max(), p.defaultValue()).isPresent()) {
                    problems.add(file + " property " + name + ": default '" + p.defaultValue()
                            + "' is not valid for its own type");
                }
            });
        final java.util.function.BiConsumer<String, List<PatternSpec>> checkPatterns = (file, pats) -> {
            for (PatternSpec p : nullSafe(pats)) {
                try {
                    Pattern.compile(p.pattern());
                } catch (PatternSyntaxException ex) {
                    problems.add(file + " pattern " + p.pattern() + ": " + ex.getDescription());
                }
                if (p.type() != null && !types.has(p.type())) {
                    problems.add(file + " pattern " + p.pattern() + ": unknown type '" + p.type() + "'");
                }
            }
        };
        final java.util.function.BiConsumer<String, RequestMetadataSpec> checkMetadata = (file, md) -> {
            if (md != null) {
                nullSafeMap(md.keys()).forEach((k, v) -> {
                    if (v.type() != null && !types.has(v.type())) {
                        problems.add(file + " request metadata " + k + ": unknown type '" + v.type() + "'");
                    }
                });
            }
        };
        final java.util.function.BiConsumer<String, List<ConditionalInherit>> checkConditionals = (file, cis) -> {
            for (ConditionalInherit ci : nullSafe(cis)) {
                PredicateEvaluator.validate(ci.when(), file + " conditionalInherits", problems);
                ci.groups().stream().filter(g -> !groups.containsKey(g)).forEach(g
                        -> problems.add(file + ": unknown group '" + g + "' in conditionalInherits"));
            }
        };

        groups.forEach((name, g) -> {
            final String file = groupFiles.get(name);
            checkProps.accept(file, g.properties());
            checkPatterns.accept(file, g.propertyPatterns());
            checkRules.accept(file, g.rules());
            checkRules.accept(file, g.combinationRules());
            checkMetadata.accept(file, g.requestMetadata());
            checkConditionals.accept(file, g.conditionalInherits());
        });
        if (!groups.containsKey(FALLBACK_GROUP)) {
            problems.add("catalog.yaml: the group '" + FALLBACK_GROUP + "' is required");
        }
        workers.forEach((name, w) -> {
            final String file = workerFiles.get(name);
            if (w.kind() == null || !KINDS.contains(w.kind())) {
                problems.add(file + ": kind must be one of " + KINDS);
            }
            if (w.match() == null || w.match().isEmpty()) {
                problems.add(file + ": 'match' must name at least IMPLEMENTATION_CLASS");
            }
            nullSafe(w.inherits()).stream().filter(g -> !groups.containsKey(g)).forEach(g
                    -> problems.add(file + ": unknown group '" + g + "' in inherits"));
            checkProps.accept(file, w.properties());
            checkPatterns.accept(file, w.propertyPatterns());
            checkRules.accept(file, w.rules());
            checkRules.accept(file, w.combinationRules());
            checkMetadata.accept(file, w.requestMetadata());
            checkConditionals.accept(file, w.conditionalInherits());
        });
        optionGroups.forEach((name, og) -> {
            final String file = optionGroupFiles.get(name);
            checkRules.accept(file, og.rules());
            checkOptions(file, og.options(), problems);
        });
        commands.values().forEach(c -> checkOptions(c.file(), c.options(), problems));
        cliFiles.forEach((file, c) -> checkRules.accept(file, c.rules()));
        checkRules.accept("combinations.yaml", combinationRules.stream().map(SourcedRule::rule).toList());

        final Map<String, GoldenTest> testsByName = new LinkedHashMap<>();
        for (SourcedTest t : tests) {
            if (testsByName.put(t.test().name(), t.test()) != null) {
                problems.add(t.file() + ": duplicate test name '" + t.test().name() + "'");
            }
        }
        for (SourcedTest t : tests) {
            final String ext = t.test().extendsTest();
            if (ext != null && !testsByName.containsKey(ext)) {
                problems.add(t.file() + " test " + t.test().name() + ": extends unknown test '" + ext + "'");
            }
            if (t.test().config() == null && t.test().cli() == null && ext == null) {
                problems.add(t.file() + " test " + t.test().name() + ": needs config and/or cli");
            }
        }
        return problems;
    }

    private void checkOptions(final String file, final Map<String, OptionSpec> options,
            final List<String> problems) {
        nullSafeMap(options).forEach((name, o) -> {
            if (o.type() != null && !types.has(o.type())) {
                problems.add(file + " option " + name + ": unknown type '" + o.type() + "'");
            }
            if (o.defaultValue() != null && types.check(o.type(), o.allowedValues(),
                    o.caseSensitive(), null, null, o.defaultValue()).isPresent()) {
                problems.add(file + " option " + name + ": default '" + o.defaultValue()
                        + "' is not valid for its own type");
            }
        });
    }

    static <T> List<T> nullSafe(final List<T> list) {
        return list == null ? Collections.emptyList() : list;
    }

    static <K, V> Map<K, V> nullSafeMap(final Map<K, V> map) {
        return map == null ? Collections.emptyMap() : map;
    }

    /** Reads all files listed in the index. */
    private static final class Builder {
        private final CatalogSource source;
        private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory())
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
        private final List<String> problems = new ArrayList<>();
        private IndexFile index;
        private ValueTypeRegistry registry;
        private final Map<String, GroupFile> groups = new LinkedHashMap<>();
        private final Map<String, String> groupFiles = new LinkedHashMap<>();
        private final Map<String, WorkerFile> workers = new LinkedHashMap<>();
        private final Map<String, String> workerFiles = new LinkedHashMap<>();
        private final Map<String, CliOptionGroupFile> optionGroups = new LinkedHashMap<>();
        private final Map<String, String> optionGroupFiles = new LinkedHashMap<>();
        private final Map<String, CliFile> cliFiles = new LinkedHashMap<>();
        private final Map<String, ResolvedCommand> commands = new LinkedHashMap<>();
        private final List<SourcedRule> combinationRules = new ArrayList<>();
        private final List<SourcedTest> tests = new ArrayList<>();

        Builder(final CatalogSource source) {
            this.source = source;
        }

        void read() throws CatalogException {
            index = readFile("catalog.yaml", IndexFile.class);
            if (index == null) {
                throw new CatalogException(problems);
            }
            final Map<String, TypeDef> typeDefs = new LinkedHashMap<>();
            final ValueTypesFile vt = readFile(index.valueTypes(), ValueTypesFile.class);
            if (vt != null) {
                typeDefs.putAll(nullSafeMap(vt.types()));
            }
            for (String f : nullSafe(index.groups())) {
                final GroupFile g = readFile(f, GroupFile.class);
                if (g != null) {
                    if (groups.put(g.group(), g) != null) {
                        problems.add(f + ": duplicate group '" + g.group() + "'");
                    }
                    groupFiles.put(g.group(), f);
                    addTypes(f, g.types(), typeDefs);
                }
            }
            for (String f : nullSafe(index.workers())) {
                final WorkerFile w = readFile(f, WorkerFile.class);
                if (w != null) {
                    if (workers.put(w.worker(), w) != null) {
                        problems.add(f + ": duplicate worker '" + w.worker() + "'");
                    }
                    workerFiles.put(w.worker(), f);
                    addTypes(f, w.types(), typeDefs);
                }
            }
            registry = new ValueTypeRegistry(typeDefs);
            for (String f : nullSafe(index.cliOptionGroups())) {
                final CliOptionGroupFile og = readFile(f, CliOptionGroupFile.class);
                if (og != null) {
                    optionGroups.put(og.optionGroup(), og);
                    optionGroupFiles.put(og.optionGroup(), f);
                }
            }
            for (String f : nullSafe(index.cli())) {
                final CliFile c = readFile(f, CliFile.class);
                if (c != null) {
                    cliFiles.put(f, c);
                    commands.put(c.command(), resolveCommand(f, c));
                }
            }
            if (index.combinations() != null) {
                final CombinationsFile cf = readFile(index.combinations(), CombinationsFile.class);
                if (cf != null) {
                    nullSafe(cf.rules()).forEach(r -> combinationRules.add(new SourcedRule(r, index.combinations())));
                }
            }
            for (String f : nullSafe(index.tests())) {
                final TestFile tf = readFile(f, TestFile.class);
                if (tf != null) {
                    nullSafe(tf.tests()).forEach(t -> tests.add(new SourcedTest(t, f)));
                }
            }
        }

        private ResolvedCommand resolveCommand(final String file, final CliFile c) {
            final Map<String, OptionSpec> options = new LinkedHashMap<>();
            final List<SourcedRule> rules = new ArrayList<>();
            for (String og : nullSafe(c.optionGroups())) {
                final CliOptionGroupFile g = optionGroups.get(og);
                if (g == null) {
                    problems.add(file + ": unknown option group '" + og + "'");
                    continue;
                }
                options.putAll(nullSafeMap(g.options()));
                nullSafe(g.rules()).forEach(r -> rules.add(new SourcedRule(r, optionGroupFiles.get(og))));
            }
            options.putAll(nullSafeMap(c.options()));
            nullSafe(c.rules()).forEach(r -> rules.add(new SourcedRule(r, file)));
            for (String wo : nullSafe(c.workerOptions())) {
                if (!options.containsKey(wo)) {
                    problems.add(file + ": workerOptions names unknown option '" + wo + "'");
                }
            }
            return new ResolvedCommand(c.command(), file, options, rules,
                    nullSafe(c.targetKinds()), nullSafe(c.workerOptions()));
        }

        private void addTypes(final String file, final Map<String, TypeDef> local,
                final Map<String, TypeDef> all) {
            nullSafeMap(local).forEach((k, v) -> {
                if (all.put(k, v) != null) {
                    problems.add(file + ": type '" + k + "' is already defined");
                }
            });
        }

        private <T> T readFile(final String file, final Class<T> clazz) {
            if (file == null) {
                problems.add("catalog.yaml: missing file reference for " + clazz.getSimpleName());
                return null;
            }
            try (InputStream in = source.open(file)) {
                final T result = yaml.readValue(in, clazz);
                if (result == null) {
                    problems.add(file + ": file is empty");
                }
                return result;
            } catch (IOException ex) {
                problems.add(file + ": " + ex.getMessage().replaceAll("\\s+", " "));
                return null;
            }
        }
    }
}
