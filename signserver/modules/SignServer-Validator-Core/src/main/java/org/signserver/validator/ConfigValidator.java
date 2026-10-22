package org.signserver.validator;

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

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.signserver.validator.catalog.CatalogModel.PropertySpec;
import org.signserver.validator.catalog.CatalogModel.WorkerFile;
import org.signserver.validator.catalog.ResolvedWorker;
import org.signserver.validator.catalog.ResolvedWorker.SourcedProperty;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.eval.EvalContext;
import org.signserver.validator.eval.PredicateEvaluator;
import org.signserver.validator.eval.RuleRunner;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.Severity;

/**
 * Validates a worker configuration: unknown, misplaced and missing
 * properties, property values and the configuration rules.
 *
 * @version $Id$
 */
public final class ConfigValidator {

    /** Placeholder SignServer exports instead of secret values. */
    public static final String MASKED = "_MASKED_";

    /** Result of a configuration validation. */
    public record Result(ResolvedWorker worker, List<Finding> findings) {
    }

    private final RuleCatalog catalog;

    public ConfigValidator(final RuleCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * @param config configuration with upper-case keys
     * @param directory other workers, or null
     * @return the resolved worker and the findings
     */
    public Result validate(final Map<String, String> config, final WorkerDirectory directory) {
        final List<Finding> out = new ArrayList<>();
        final ResolvedWorker w = catalog.resolve(config);
        final String impl = config.get("IMPLEMENTATION_CLASS");

        if (!w.isKnown() && impl != null && !impl.isBlank()) {
            out.add(Finding.of(Severity.WARNING, "WORKER_TYPE_UNKNOWN",
                    "The rule catalog " + catalog.getCatalogVersion() + " has no rules for "
                    + describeMatch(config) + "; only the properties common to all workers are checked")
                    .withProperty("IMPLEMENTATION_CLASS")
                    .withSuggestion("Add a worker file to validator-rules/workers/ for this worker type"));
        }

        for (Map.Entry<String, String> e : new TreeMap<>(config).entrySet()) {
            final String name = e.getKey();
            if (name.startsWith("__")) {
                continue;
            }
            final String value = e.getValue() == null ? "" : e.getValue().trim();
            final Optional<SourcedProperty> p = w.property(name);
            if (p.isPresent()) {
                checkValue(p.get(), value, w.getName(), Severity.parse(p.get().spec().invalidSeverity(), Severity.ERROR), out);
                if (p.get().spec().deprecated() != null) {
                    out.add(Finding.of(Severity.WARNING, "PROP_DEPRECATED", p.get().spec().deprecated())
                            .withProperty(name).withRuleSource(p.get().file()));
                }
            } else if (w.isKnown()) {
                checkUndeclared(w, name, value, out);
            }
        }

        for (SourcedProperty p : w.getProperties().values()) {
            if (Boolean.TRUE.equals(p.spec().required())) {
                final String v = config.get(p.name());
                if (v == null || v.trim().isEmpty()) {
                    out.add(Finding.of(Severity.ERROR, "PROP_MISSING",
                            p.name() + " is required" + (p.spec().description() != null
                            ? " (" + p.spec().description() + ")" : ""))
                            .withProperty(p.name()).withRuleSource(p.file()));
                }
            }
        }

        RuleRunner.run(w.getRules(), new EvalContext(config, w, null, directory, catalog), out);
        return new Result(w, sorted(out));
    }

    private void checkValue(final SourcedProperty p, final String value, final String workerName,
            final Severity severity, final List<Finding> out) {
        if (value.isEmpty() || value.equals(MASKED)) {
            return;
        }
        final PropertySpec s = p.spec();
        final Optional<String> problem = catalog.getTypes().check(s.type(), s.allowedValues(),
                s.caseSensitive(), s.min(), s.max(), value);
        problem.ifPresent(expected -> out.add(Finding.of(severity, "VALUE_INVALID",
                "'" + Names.show(value, Boolean.TRUE.equals(s.sensitive())) + "' is not a valid "
                + p.name() + " for " + workerName + ": expected " + expected)
                .withProperty(p.name()).withRuleSource(p.file())));
    }

    private void checkUndeclared(final ResolvedWorker w, final String name, final String value,
            final List<Finding> out) {
        final Set<String> owners = new TreeSet<>(catalog.ownersOf(name));
        owners.remove(w.getName());
        final List<JsonNode> conditions = catalog.conditionsDeclaring(w.getName(), name);
        if (!conditions.isEmpty()) {
            out.add(Finding.of(Severity.WARNING, "PROP_NOT_APPLICABLE",
                    name + " is not used by " + w.getName() + " with this configuration; it only applies when "
                    + conditions.stream().map(PredicateEvaluator::describe).collect(Collectors.joining(" or ")))
                    .withProperty(name).withRuleSource(w.getFile())
                    .withSuggestion(owners.isEmpty() ? "Remove it"
                            : "It is a property of " + String.join(", ", owners)
                            + "; move it to that worker (e.g. the crypto worker named in CRYPTOTOKEN)"));
            return;
        }
        final Optional<String> similar = Names.closest(name, w.getProperties().keySet());
        if (!owners.isEmpty()) {
            final String ownerList = String.join(", ", owners);
            out.add(Finding.of(Severity.ERROR, "PROP_WRONG_WORKER",
                    name + " is not valid for " + w.getName() + " (it is a property of " + ownerList + ")")
                    .withProperty(name).withRuleSource(w.getFile())
                    .withSuggestion(similar.map(s -> "Did you mean " + s + "? Otherwise remove it")
                            .orElse("Remove it, or use a worker of type " + ownerList)));
            // Also tell when the value would not even be valid for the owner
            if (!value.isEmpty()) {
                final String owner = owners.iterator().next();
                final WorkerFile ownerFile = catalog.getWorkers().get(owner);
                catalog.resolve(ownerFile.match()).property(name).ifPresent(p
                        -> checkValue(p, value, owner, Severity.ERROR, out));
            }
            return;
        }
        final Optional<String> anyKnown = similar.isPresent() ? similar
                : Names.closest(name, catalog.allPropertyNames());
        out.add(Finding.of(Severity.WARNING, "PROP_UNKNOWN",
                name + " is not a known property of " + w.getName() + " and will be ignored")
                .withProperty(name).withRuleSource(w.getFile())
                .withSuggestion(anyKnown.map(s -> "Did you mean " + s + "?").orElse(null)));
    }

    private static String describeMatch(final Map<String, String> config) {
        final String token = config.get("CRYPTOTOKEN_IMPLEMENTATION_CLASS");
        return "IMPLEMENTATION_CLASS=" + config.get("IMPLEMENTATION_CLASS")
                + (token != null && !token.isBlank() ? " with CRYPTOTOKEN_IMPLEMENTATION_CLASS=" + token : "");
    }

    /** @return the findings ordered ERROR, WARNING, INFO keeping the order within a severity */
    static List<Finding> sorted(final List<Finding> findings) {
        final List<Finding> result = new ArrayList<>(findings);
        result.sort((a, b) -> a.severity().compareTo(b.severity()));
        return result;
    }
}
