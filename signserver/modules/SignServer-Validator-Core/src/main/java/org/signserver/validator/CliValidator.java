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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.signserver.validator.catalog.CatalogModel.OptionSpec;
import org.signserver.validator.catalog.ResolvedCommand;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.cli.CommandLineTokenizer;
import org.signserver.validator.cli.ParsedCommand;
import org.signserver.validator.eval.EvalContext;
import org.signserver.validator.eval.RuleRunner;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.Severity;

/**
 * Validates a signclient command line on its own: command, option names,
 * option arguments and values, and the command rules.
 *
 * <p>Parsing follows commons-cli as used by signclient: options start with
 * "-" (or "--"), are case-sensitive and an option taking an argument uses
 * the next token. "-option=value" is accepted too.</p>
 *
 * @version $Id$
 */
public final class CliValidator {

    /** Result of a CLI validation; parsed is null when nothing could be parsed. */
    public record Result(ParsedCommand parsed, List<Finding> findings) {
    }

    private static final Pattern PROGRAM = Pattern.compile("(.*[/\\\\])?signclient(\\.sh|\\.cmd|\\.bat)?");
    private static final Pattern NEGATIVE_NUMBER = Pattern.compile("-\\d+");

    private final RuleCatalog catalog;

    public CliValidator(final RuleCatalog catalog) {
        this.catalog = catalog;
    }

    /**
     * @param line the command line, optionally starting with "signclient"
     * @return the parsed command (if any) and the findings
     */
    public Result validate(final String line) {
        final List<Finding> out = new ArrayList<>();
        final List<String> tokens;
        try {
            tokens = new ArrayList<>(CommandLineTokenizer.tokenize(line));
        } catch (IllegalArgumentException ex) {
            out.add(Finding.of(Severity.ERROR, "CLI_SYNTAX", "The command line can not be parsed: " + ex.getMessage()));
            return new Result(null, out);
        }
        if (!tokens.isEmpty() && PROGRAM.matcher(tokens.get(0)).matches()) {
            tokens.remove(0);
        }
        if (tokens.isEmpty()) {
            out.add(Finding.of(Severity.ERROR, "CLI_MISSING_COMMAND",
                    "No signclient command given; expected one of " + catalog.getCommands().keySet()));
            return new Result(null, out);
        }
        final String commandName = tokens.get(0);
        final ResolvedCommand spec = catalog.getCommands().get(commandName);
        if (spec == null) {
            final Optional<String> similar = Names.closest(commandName, catalog.getCommands().keySet());
            out.add(Finding.of(Severity.ERROR, "CLI_UNKNOWN_COMMAND",
                    "'" + commandName + "' is not a known signclient command; expected one of "
                    + catalog.getCommands().keySet())
                    .withSuggestion(similar.map(s -> "Did you mean " + s + "?").orElse(null)));
            return new Result(new ParsedCommand(null, commandName, Collections.emptyMap(), tokens.subList(1, tokens.size())), out);
        }

        final Map<String, List<String>> options = new LinkedHashMap<>();
        final List<String> positionals = new ArrayList<>();
        for (int i = 1; i < tokens.size(); i++) {
            final String t = tokens.get(i);
            if (!t.startsWith("-") || t.equals("-") || NEGATIVE_NUMBER.matcher(t).matches()) {
                positionals.add(t);
                continue;
            }
            String name = t.startsWith("--") ? t.substring(2) : t.substring(1);
            String inline = null;
            final int eq = name.indexOf('=');
            if (eq > 0) {
                inline = name.substring(eq + 1);
                name = name.substring(0, eq);
            }
            final OptionSpec o = spec.options().get(name);
            final boolean nextIsValue = i + 1 < tokens.size() && !isKnownOption(spec, tokens.get(i + 1));
            if (o == null) {
                final Optional<String> similar = Names.closest(name, spec.options().keySet());
                out.add(Finding.of(Severity.ERROR, "CLI_UNKNOWN_OPTION",
                        "-" + name + " is not an option of " + commandName)
                        .withOption(name)
                        .withSuggestion(similar.map(s -> "Did you mean -" + s + "? (options are case-sensitive)").orElse(null)));
                if (inline == null && nextIsValue && !tokens.get(i + 1).startsWith("-")) {
                    i++; // most likely the argument of the unknown option
                }
                continue;
            }
            if (options.containsKey(name) && !Boolean.TRUE.equals(o.repeatable())) {
                out.add(Finding.of(Severity.WARNING, "CLI_DUPLICATE_OPTION",
                        "-" + name + " is given more than once; only the first value is used").withOption(name));
            }
            final List<String> values = options.computeIfAbsent(name, k -> new ArrayList<>());
            if (Boolean.TRUE.equals(o.arg())) {
                if (inline != null) {
                    values.add(inline);
                } else if (nextIsValue) {
                    values.add(tokens.get(++i));
                } else {
                    out.add(Finding.of(Severity.ERROR, "CLI_MISSING_ARGUMENT",
                            "-" + name + " needs a value").withOption(name));
                }
            } else if (inline != null) {
                out.add(Finding.of(Severity.WARNING, "CLI_UNEXPECTED_ARGUMENT",
                        "-" + name + " does not take a value; '" + inline + "' is ignored").withOption(name));
            }
        }
        if (!positionals.isEmpty()) {
            out.add(Finding.of(Severity.WARNING, "CLI_UNEXPECTED_ARGUMENT",
                    "These arguments belong to no option and are ignored: " + String.join(" ", positionals)));
        }

        final ParsedCommand parsed = new ParsedCommand(spec, commandName, options, positionals);
        options.forEach((name, values) -> {
            final OptionSpec o = spec.options().get(name);
            for (String v : values) {
                catalog.getTypes().check(o.type(), o.allowedValues(), o.caseSensitive(), null, null, v)
                        .ifPresent(expected -> out.add(Finding.of(Severity.ERROR, "CLI_VALUE_INVALID",
                                "'" + Names.show(v, Boolean.TRUE.equals(o.sensitive())) + "' is not a valid value for -"
                                + name + ": expected " + expected).withOption(name)));
            }
        });

        RuleRunner.run(spec.rules(), new EvalContext(null, null, parsed, null, catalog), out);
        return new Result(parsed, ConfigValidator.sorted(out));
    }

    private static boolean isKnownOption(final ResolvedCommand spec, final String token) {
        if (!token.startsWith("-") || NEGATIVE_NUMBER.matcher(token).matches()) {
            return false;
        }
        String name = token.startsWith("--") ? token.substring(2) : token.substring(1);
        final int eq = name.indexOf('=');
        if (eq > 0) {
            name = name.substring(0, eq);
        }
        return spec.options().containsKey(name);
    }
}
