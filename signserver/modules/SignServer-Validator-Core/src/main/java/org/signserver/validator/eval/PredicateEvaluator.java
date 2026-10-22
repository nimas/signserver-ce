package org.signserver.validator.eval;

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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Evaluates the closed predicate language used by "when", "require" and
 * "conditionalInherits" in the catalog. A predicate is a YAML object with
 * exactly one key; see validator-rules/README.md for the list.
 *
 * <p>Property comparisons (isTrue, equals, in, ...) use the effective value:
 * the configured value, else the default declared in the catalog. "present"
 * and "absent" look at the configured value only.</p>
 *
 * @version $Id$
 */
public final class PredicateEvaluator {

    /** Every predicate key the engine understands. */
    public static final Set<String> KEYS = Set.of("present", "absent",
            "presentMatching", "isTrue", "isFalse", "anyTrue", "allTrue",
            "equals", "in", "matches", "listExcludes", "all", "any",
            "exactlyOne", "atMostOne", "not", "cli.command", "cli.hasOption",
            "cli.optionEquals", "cli.optionIn", "cli.optionMatches",
            "cli.optionValueInList", "worker.kind", "worker.is",
            "worker.hasCapability", "worker.known", "directory.workerExists",
            "directory.workerKind", "custom");

    private static final Map<String, CustomPredicate> CUSTOM = new HashMap<>();

    static {
        for (CustomPredicate p : ServiceLoader.load(CustomPredicate.class)) {
            CUSTOM.put(p.id(), p);
        }
    }

    private PredicateEvaluator() {
    }

    /**
     * Checks the structure of a predicate (used when loading the catalog).
     *
     * @param node the predicate
     * @param where location used in problem messages
     * @param problems where to add problems
     */
    public static void validate(final JsonNode node, final String where, final List<String> problems) {
        if (node == null || !node.isObject() || node.size() != 1) {
            problems.add(where + ": a predicate must be an object with exactly one key, got " + node);
            return;
        }
        final String key = node.fieldNames().next();
        final JsonNode arg = node.get(key);
        if (!KEYS.contains(key)) {
            problems.add(where + ": unknown predicate '" + key + "', expected one of " + KEYS);
            return;
        }
        switch (key) {
            case "all", "any", "exactlyOne", "atMostOne" -> {
                if (!arg.isArray() || arg.isEmpty()) {
                    problems.add(where + ": '" + key + "' needs a non-empty list of predicates");
                } else {
                    arg.forEach(a -> validate(a, where + "/" + key, problems));
                }
            }
            case "not" -> validate(arg, where + "/not", problems);
            case "present", "absent", "isTrue", "isFalse", "cli.hasOption",
                    "worker.hasCapability", "directory.workerExists" -> {
                if (!arg.isTextual()) {
                    problems.add(where + ": '" + key + "' needs a name");
                }
            }
            case "presentMatching" -> checkRegex(arg.asText(), where, problems);
            case "matches", "cli.optionMatches" -> arg.fields().forEachRemaining(e
                    -> checkRegex(e.getValue().asText(), where, problems));
            case "anyTrue", "allTrue" -> {
                if (!arg.isArray()) {
                    problems.add(where + ": '" + key + "' needs a list of property names");
                }
            }
            case "equals", "in", "cli.optionEquals", "cli.optionIn" -> {
                if (!arg.isObject() || arg.size() != 1) {
                    problems.add(where + ": '" + key + "' needs exactly one NAME: value entry");
                }
            }
            case "custom" -> {
                final String id = arg.path("check").asText(null);
                if (id == null) {
                    problems.add(where + ": 'custom' needs 'check: <id>'");
                } else if (!CUSTOM.containsKey(id)) {
                    problems.add(where + ": no CustomPredicate registered with id '" + id + "'");
                }
            }
            default -> {
                // other predicates take structured arguments checked by the JSON Schema
            }
        }
    }

    private static void checkRegex(final String regex, final String where, final List<String> problems) {
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException ex) {
            problems.add(where + ": invalid regular expression '" + regex + "': " + ex.getDescription());
        }
    }

    /**
     * @param node the predicate
     * @param ctx what can be looked at
     * @return the result
     */
    public static Tri evaluate(final JsonNode node, final EvalContext ctx) {
        final String key = node.fieldNames().next();
        final JsonNode arg = node.get(key);
        return switch (key) {
            case "all" -> all(arg, ctx);
            case "any" -> any(arg, ctx);
            case "not" -> evaluate(arg, ctx).not();
            case "exactlyOne" -> count(arg, ctx, n -> n == 1);
            case "atMostOne" -> count(arg, ctx, n -> n <= 1);

            case "present" -> config(ctx, () -> Tri.of(ctx.value(arg.asText()) != null));
            case "absent" -> config(ctx, () -> Tri.of(ctx.value(arg.asText()) == null));
            case "presentMatching" -> config(ctx, () -> {
                final Pattern p = Pattern.compile(arg.asText());
                return Tri.of(ctx.config().entrySet().stream().anyMatch(e
                        -> p.matcher(e.getKey()).matches() && e.getValue() != null
                        && !e.getValue().trim().isEmpty()));
            });
            case "isTrue" -> config(ctx, () -> Tri.of("TRUE".equalsIgnoreCase(ctx.effective(arg.asText()))));
            case "isFalse" -> config(ctx, () -> Tri.of("FALSE".equalsIgnoreCase(ctx.effective(arg.asText()))));
            case "anyTrue" -> config(ctx, () -> Tri.of(texts(arg).stream()
                    .anyMatch(p -> "TRUE".equalsIgnoreCase(ctx.effective(p)))));
            case "allTrue" -> config(ctx, () -> Tri.of(texts(arg).stream()
                    .allMatch(p -> "TRUE".equalsIgnoreCase(ctx.effective(p)))));
            case "equals" -> config(ctx, () -> entry(arg, (name, expected)
                    -> Tri.of(expected.asText().equalsIgnoreCase(nullToEmpty(ctx.effective(name))))));
            case "in" -> config(ctx, () -> entry(arg, (name, values) -> {
                final String v = ctx.effective(name);
                return Tri.of(v != null && texts(values).stream().anyMatch(v::equalsIgnoreCase));
            }));
            case "matches" -> config(ctx, () -> entry(arg, (name, regex) -> {
                final String v = ctx.effective(name);
                return Tri.of(v != null && Pattern.matches(regex.asText(), v));
            }));
            case "listExcludes" -> config(ctx, () -> {
                final String v = ctx.effective(arg.path("property").asText());
                if (v == null) {
                    return Tri.TRUE;
                }
                final List<String> forbidden = texts(arg.path("values"));
                return Tri.of(Arrays.stream(v.split(",")).map(String::trim)
                        .noneMatch(item -> forbidden.stream().anyMatch(item::equalsIgnoreCase)));
            });

            case "cli.command" -> cli(ctx, () -> Tri.of(texts(arg).contains(ctx.cli().command())));
            case "cli.hasOption" -> cli(ctx, () -> Tri.of(ctx.cli().hasOption(arg.asText())));
            case "cli.optionEquals" -> cli(ctx, () -> entry(arg, (opt, expected)
                    -> Tri.of(expected.asText().equals(ctx.cli().effectiveValue(opt)))));
            case "cli.optionIn" -> cli(ctx, () -> entry(arg, (opt, values)
                    -> Tri.of(texts(values).contains(ctx.cli().effectiveValue(opt)))));
            case "cli.optionMatches" -> cli(ctx, () -> entry(arg, (opt, regex) -> {
                final String v = ctx.cli().effectiveValue(opt);
                return Tri.of(v != null && Pattern.matches(regex.asText(), v));
            }));
            case "cli.optionValueInList" -> optionValueInList(arg, ctx);

            case "worker.known" -> worker(ctx, () -> Tri.of(ctx.worker().isKnown() == arg.asBoolean()), false);
            case "worker.kind" -> worker(ctx, () -> Tri.of(texts(arg).contains(ctx.worker().getKind())), true);
            case "worker.is" -> worker(ctx, () -> Tri.of(texts(arg).contains(ctx.worker().getName())), true);
            case "worker.hasCapability" -> worker(ctx, () -> Tri.of(ctx.worker().getCapabilities().contains(arg.asText())), true);

            case "directory.workerExists" -> directory(ctx, arg.asText(), other -> Tri.TRUE);
            case "directory.workerKind" -> directory(ctx, arg.path("property").asText(), other
                    -> Tri.of(arg.path("kind").asText().equals(ctx.catalog().kindOf(other))));

            case "custom" -> {
                final CustomPredicate p = CUSTOM.get(arg.path("check").asText());
                yield p == null ? Tri.UNKNOWN : p.evaluate(arg, ctx);
            }
            default -> throw new IllegalArgumentException("Unknown predicate: " + key);
        };
    }

    /**
     * @param node a predicate
     * @return a short human-readable form, e.g. "CRYPTOTOKEN_IMPLEMENTATION_CLASS=...KeystoreCryptoToken"
     */
    public static String describe(final JsonNode node) {
        final String key = node.fieldNames().next();
        final JsonNode arg = node.get(key);
        return switch (key) {
            case "all" -> join(arg, " and ");
            case "any" -> join(arg, " or ");
            case "not" -> "not (" + describe(arg) + ")";
            case "present" -> arg.asText() + " is set";
            case "absent" -> arg.asText() + " is not set";
            case "isTrue" -> arg.asText() + "=TRUE";
            case "isFalse" -> arg.asText() + "=FALSE";
            case "equals" -> entry(arg, (name, v) -> name + "=" + v.asText());
            case "in" -> entry(arg, (name, v) -> name + " is one of " + texts(v));
            default -> node.toString();
        };
    }

    private static String join(final JsonNode list, final String separator) {
        final List<String> parts = new ArrayList<>();
        list.forEach(n -> parts.add(describe(n)));
        return String.join(separator, parts);
    }

    private static Tri all(final JsonNode list, final EvalContext ctx) {
        Tri result = Tri.TRUE;
        for (JsonNode n : list) {
            final Tri t = evaluate(n, ctx);
            if (t == Tri.FALSE) {
                return Tri.FALSE;
            }
            if (t == Tri.UNKNOWN) {
                result = Tri.UNKNOWN;
            }
        }
        return result;
    }

    private static Tri any(final JsonNode list, final EvalContext ctx) {
        Tri result = Tri.FALSE;
        for (JsonNode n : list) {
            final Tri t = evaluate(n, ctx);
            if (t == Tri.TRUE) {
                return Tri.TRUE;
            }
            if (t == Tri.UNKNOWN) {
                result = Tri.UNKNOWN;
            }
        }
        return result;
    }

    private static Tri count(final JsonNode list, final EvalContext ctx,
            final java.util.function.IntPredicate accept) {
        int trues = 0;
        int unknowns = 0;
        for (JsonNode n : list) {
            final Tri t = evaluate(n, ctx);
            if (t == Tri.TRUE) {
                trues++;
            } else if (t == Tri.UNKNOWN) {
                unknowns++;
            }
        }
        if (unknowns == 0) {
            return Tri.of(accept.test(trues));
        }
        // Result is known only if every possible outcome agrees
        boolean anyAccepted = false;
        boolean anyRejected = false;
        for (int n = trues; n <= trues + unknowns; n++) {
            if (accept.test(n)) {
                anyAccepted = true;
            } else {
                anyRejected = true;
            }
        }
        return anyAccepted && anyRejected ? Tri.UNKNOWN : Tri.of(anyAccepted);
    }

    private static Tri optionValueInList(final JsonNode arg, final EvalContext ctx) {
        if (ctx.cli() == null || ctx.config() == null) {
            return Tri.UNKNOWN;
        }
        final String value = ctx.cli().effectiveValue(arg.path("option").asText());
        final String list = ctx.effective(arg.path("property").asText());
        if (value == null || list == null) {
            return Tri.TRUE;
        }
        final String mode = arg.path("normalize").asText("none");
        final Function<String, String> norm = switch (mode) {
            case "digest" -> ValueTypeRegistry::normalizeDigest;
            case "upper" -> s -> s.trim().toUpperCase();
            default -> String::trim;
        };
        final String v = norm.apply(value);
        return Tri.of(Arrays.stream(list.split(",")).filter(s -> !s.isBlank())
                .map(norm).anyMatch(v::equals));
    }

    private static Tri config(final EvalContext ctx, final java.util.function.Supplier<Tri> s) {
        return ctx.config() == null ? Tri.UNKNOWN : s.get();
    }

    private static Tri cli(final EvalContext ctx, final java.util.function.Supplier<Tri> s) {
        return ctx.cli() == null ? Tri.UNKNOWN : s.get();
    }

    private static Tri worker(final EvalContext ctx, final java.util.function.Supplier<Tri> s,
            final boolean needsKnown) {
        if (ctx.worker() == null || (needsKnown && !ctx.worker().isKnown())) {
            return Tri.UNKNOWN;
        }
        return s.get();
    }

    private static Tri directory(final EvalContext ctx, final String property,
            final Function<Map<String, String>, Tri> onFound) {
        if (ctx.config() == null) {
            return Tri.UNKNOWN;
        }
        final String ref = ctx.value(property);
        if (ref == null) {
            return Tri.TRUE;
        }
        if (ctx.directory() == null) {
            return Tri.UNKNOWN;
        }
        final Optional<Map<String, String>> other = ctx.directory().find(ref);
        if (other.isEmpty()) {
            return ctx.directory().isComplete() ? Tri.FALSE : Tri.UNKNOWN;
        }
        return onFound.apply(other.get());
    }

    private static <T> T entry(final JsonNode obj,
            final java.util.function.BiFunction<String, JsonNode, T> f) {
        final Iterator<Map.Entry<String, JsonNode>> it = obj.fields();
        final Map.Entry<String, JsonNode> e = it.next();
        return f.apply(e.getKey(), e.getValue());
    }

    private static List<String> texts(final JsonNode node) {
        final List<String> result = new ArrayList<>();
        if (node.isArray()) {
            node.forEach(n -> result.add(n.asText()));
        } else if (!node.isMissingNode() && !node.isNull()) {
            result.add(node.asText());
        }
        return result;
    }

    private static String nullToEmpty(final String s) {
        return s == null ? "" : s;
    }
}
