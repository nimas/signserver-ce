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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.signserver.validator.catalog.CatalogModel.MetadataKeySpec;
import org.signserver.validator.catalog.ResolvedCommand;
import org.signserver.validator.catalog.ResolvedWorker;
import org.signserver.validator.catalog.ResolvedWorker.SourcedMetadataKey;
import org.signserver.validator.catalog.ResolvedWorker.SourcedRule;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.cli.ParsedCommand;
import org.signserver.validator.eval.EvalContext;
import org.signserver.validator.eval.RuleRunner;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.Severity;

/**
 * Validates a signclient command against the configuration of the worker it
 * targets: worker kind, target name, request metadata and the combination
 * rules.
 *
 * @version $Id$
 */
public final class CombinationValidator {

    private static final String METADATA_OPTION = "metadata";

    private final RuleCatalog catalog;

    public CombinationValidator(final RuleCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * @param config configuration with upper-case keys
     * @param worker resolved worker of the configuration
     * @param cli the parsed command (spec must be known)
     * @param directory other workers, or null
     * @return the findings
     */
    public List<Finding> validate(final Map<String, String> config, final ResolvedWorker worker,
            final ParsedCommand cli, final WorkerDirectory directory) {
        final List<Finding> out = new ArrayList<>();
        final ResolvedCommand spec = cli.spec();
        final EvalContext ctx = new EvalContext(config, worker, cli, directory, catalog);

        checkKind(spec, worker, out);
        checkTarget(spec, cli, config, out);
        if (worker.isKnown()) {
            checkMetadata(cli, worker, ctx, out);
        }

        final List<SourcedRule> rules = new ArrayList<>(catalog.getCombinationRules());
        rules.addAll(worker.getCombinationRules());
        RuleRunner.run(rules, ctx, out);
        return ConfigValidator.sorted(out);
    }

    private void checkKind(final ResolvedCommand spec, final ResolvedWorker worker, final List<Finding> out) {
        if (spec.targetKinds().isEmpty() || worker.getKind() == null) {
            return;
        }
        if (!spec.targetKinds().contains(worker.getKind())) {
            out.add(Finding.of(Severity.ERROR, "COMBO_WRONG_WORKER_KIND",
                    spec.command() + " needs a worker of kind " + String.join(" or ", spec.targetKinds())
                    + " but " + worker.getName() + " is a " + worker.getKind() + " worker")
                    .withRuleSource(spec.file()));
        }
    }

    private void checkTarget(final ResolvedCommand spec, final ParsedCommand cli,
            final Map<String, String> config, final List<Finding> out) {
        for (String option : spec.workerOptions()) {
            final String v = cli.value(option);
            if (v == null) {
                continue;
            }
            final String name = config.get("NAME");
            final String id = config.get(WorkerDirectory.WORKERID_KEY);
            final boolean matches = v.equalsIgnoreCase(name) || v.equals(id);
            final boolean comparable = name != null || id != null;
            if (comparable && !matches) {
                out.add(Finding.of(Severity.WARNING, "COMBO_TARGET_MISMATCH",
                        "The command targets worker '" + v + "' (-" + option + ") but the configuration validated is "
                        + (name != null ? "'" + name + "'" : "worker " + id))
                        .withOption(option));
            }
        }
    }

    private void checkMetadata(final ParsedCommand cli, final ResolvedWorker worker, final EvalContext ctx,
            final List<Finding> out) {
        for (String entry : cli.values(METADATA_OPTION)) {
            final int eq = entry.indexOf('=');
            if (eq <= 0) {
                continue; // reported as CLI_VALUE_INVALID
            }
            final String key = entry.substring(0, eq).trim();
            final String value = entry.substring(eq + 1).trim();
            final SourcedMetadataKey md = worker.getMetadataKeys().get(key);
            if (md == null) {
                if (!worker.isMetadataAllowUnknown()) {
                    final Optional<String> similar = Names.closest(key, worker.getMetadataKeys().keySet());
                    final boolean isProperty = worker.property(key.toUpperCase()).isPresent();
                    out.add(Finding.of(Severity.WARNING, "META_UNKNOWN",
                            "Request metadata '" + key + "' is not used by " + worker.getName()
                            + (isProperty ? " (it is a worker property, but it can not be set per request)" : "")
                            + " and will be ignored")
                            .withOption(METADATA_OPTION).withProperty(key)
                            .withSuggestion(similar.map(s -> "Did you mean " + s + "?").orElse(null))
                            .withRuleSource(worker.getFile()));
                }
                continue;
            }
            final MetadataKeySpec s = md.spec();
            if (s.requiresTrue() != null && !"TRUE".equalsIgnoreCase(ctx.effective(s.requiresTrue()))) {
                out.add(Finding.of(Severity.ERROR, "META_OVERRIDE_NOT_ALLOWED",
                        "Overriding " + key + " in the request is not allowed by the worker")
                        .withOption(METADATA_OPTION).withProperty(key)
                        .withSuggestion("Set " + s.requiresTrue() + "=TRUE on the worker or remove -metadata " + key)
                        .withRuleSource(md.file()));
            }
            if (s.requiresListed() != null) {
                final String list = ctx.effective(s.requiresListed());
                final boolean listed = list != null && Arrays.stream(list.split(","))
                        .map(String::trim).anyMatch(key::equals);
                if (!listed) {
                    out.add(Finding.of(Severity.ERROR, "META_OVERRIDE_NOT_ALLOWED",
                            "Overriding " + key + " in the request is not permitted by the worker")
                            .withOption(METADATA_OPTION).withProperty(key)
                            .withSuggestion("Add " + key + " to " + s.requiresListed() + " on the worker or remove -metadata " + key)
                            .withRuleSource(md.file()));
                }
            }
            if (!value.isEmpty()) {
                catalog.getTypes().check(s.type(), s.allowedValues(), null, null, null, value)
                        .ifPresent(expected -> out.add(Finding.of(Severity.ERROR, "META_VALUE_INVALID",
                                "'" + Names.show(value, false) + "' is not a valid value for request metadata "
                                + key + ": expected " + expected)
                                .withOption(METADATA_OPTION).withProperty(key).withRuleSource(md.file())));
            }
        }
    }
}
