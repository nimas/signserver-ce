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

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.signserver.validator.catalog.CatalogModel.TypeDef;

/**
 * The value types of the catalog (value-types.yaml plus worker-local types)
 * and the checks behind each kind.
 *
 * @version $Id$
 */
public final class ValueTypeRegistry {

    /** Kinds implemented by the engine. Adding one means adding code here. */
    public static final Set<String> KINDS = Set.of("enum", "integer", "string",
            "regex", "url", "path", "list", "oneOf", "digestAlgorithm",
            "signatureAlgorithm");

    private static final Provider BC = new BouncyCastleProvider();

    private final Map<String, TypeDef> types;
    private final Map<String, Pattern> patterns = new HashMap<>();

    public ValueTypeRegistry(final Map<String, TypeDef> types) {
        this.types = new LinkedHashMap<>(types);
    }

    public boolean has(final String name) {
        return types.containsKey(name);
    }

    /**
     * @return problems in the type definitions (unknown kinds, broken
     * references, invalid regular expressions)
     */
    public List<String> validateDefinitions() {
        final List<String> problems = new ArrayList<>();
        types.forEach((name, def) -> {
            if (def.kind() == null || !KINDS.contains(def.kind())) {
                problems.add("Type '" + name + "' has unknown kind '" + def.kind() + "', expected one of " + KINDS);
                return;
            }
            switch (def.kind()) {
                case "enum" -> {
                    if (def.values() == null || def.values().isEmpty()) {
                        problems.add("Enum type '" + name + "' has no values");
                    }
                }
                case "regex" -> {
                    if (def.pattern() == null) {
                        problems.add("Regex type '" + name + "' has no pattern");
                    } else {
                        try {
                            pattern(name, def.pattern());
                        } catch (PatternSyntaxException ex) {
                            problems.add("Regex type '" + name + "' has an invalid pattern: " + ex.getDescription());
                        }
                    }
                }
                case "list" -> {
                    if (def.of() == null || !types.containsKey(def.of())) {
                        problems.add("List type '" + name + "' refers to unknown item type '" + def.of() + "'");
                    }
                }
                case "oneOf" -> {
                    if (def.types() == null || def.types().isEmpty()) {
                        problems.add("oneOf type '" + name + "' has no types");
                    } else {
                        def.types().stream().filter(t -> !types.containsKey(t)).forEach(t
                                -> problems.add("oneOf type '" + name + "' refers to unknown type '" + t + "'"));
                    }
                }
                default -> {
                    // no settings to check
                }
            }
        });
        return problems;
    }

    /**
     * Checks a value against a type plus the optional restrictions of a
     * property or option.
     *
     * @param typeName name of the type, null means "string"
     * @param allowedValues optional restriction of the allowed values
     * @param caseSensitive whether allowedValues are compared case-sensitively
     * @param min optional minimum for numeric values
     * @param max optional maximum for numeric values
     * @param value the value (not blank)
     * @return empty when valid, otherwise a description of what was expected
     */
    public Optional<String> check(final String typeName, final List<String> allowedValues,
            final Boolean caseSensitive, final Long min, final Long max, final String value) {
        if (allowedValues != null && !allowedValues.isEmpty()) {
            final boolean cs = Boolean.TRUE.equals(caseSensitive);
            final String v = value.trim();
            final boolean found = allowedValues.stream().anyMatch(a -> cs ? a.equals(v) : a.equalsIgnoreCase(v));
            if (!found) {
                return Optional.of("one of " + String.join(", ", allowedValues)
                        + (cs ? " (case-sensitive)" : ""));
            }
        }
        final Optional<String> typeProblem = check(typeName == null ? "string" : typeName, value);
        if (typeProblem.isPresent()) {
            return typeProblem;
        }
        if (min != null || max != null) {
            try {
                final long l = Long.parseLong(value.trim());
                if ((min != null && l < min) || (max != null && l > max)) {
                    return Optional.of("a number" + (min != null ? " >= " + min : "")
                            + (max != null ? " <= " + max : ""));
                }
            } catch (NumberFormatException ex) {
                return Optional.of("a number");
            }
        }
        return Optional.empty();
    }

    /**
     * @param typeName name of the type
     * @param value the value
     * @return empty when valid, otherwise a description of what was expected
     */
    public Optional<String> check(final String typeName, final String value) {
        final TypeDef def = types.get(typeName);
        if (def == null) {
            return Optional.of("a value of unknown type '" + typeName + "' (catalog error)");
        }
        final String v = value.trim();
        final boolean ok = switch (def.kind()) {
            case "string" -> true;
            case "path" -> !v.isEmpty() && v.indexOf('\0') < 0;
            case "enum" -> !Boolean.FALSE.equals(def.caseInsensitive())
                    ? def.values().stream().anyMatch(v::equalsIgnoreCase)
                    : def.values().contains(v);
            case "integer" -> isInteger(v, def.min(), def.max());
            case "regex" -> pattern(typeName, def.pattern()).matcher(v).matches();
            case "url" -> isUrl(v);
            case "digestAlgorithm" -> isDigestAlgorithm(v);
            case "signatureAlgorithm" -> isSignatureAlgorithm(v);
            case "list" -> isList(def, v);
            case "oneOf" -> def.types().stream().anyMatch(t -> check(t, v).isEmpty());
            default -> false;
        };
        return ok ? Optional.empty() : Optional.of(describe(typeName));
    }

    /** @return human-readable description of the type */
    public String describe(final String typeName) {
        final TypeDef def = types.get(typeName);
        if (def == null) {
            return typeName;
        }
        if (def.description() != null) {
            return def.description();
        }
        return switch (def.kind()) {
            case "enum" -> "one of " + String.join(", ", def.values());
            case "integer" -> "an integer" + (def.min() != null ? " >= " + def.min() : "")
                    + (def.max() != null ? " <= " + def.max() : "");
            case "url" -> "an http(s) URL";
            case "path" -> "a file path";
            case "regex" -> "a value matching " + def.pattern();
            case "list" -> "a '" + separator(def) + "'-separated list of " + describe(def.of());
            default -> typeName;
        };
    }

    private boolean isList(final TypeDef def, final String value) {
        for (String item : value.split(Pattern.quote(separator(def)))) {
            if (!item.trim().isEmpty() && check(def.of(), item).isPresent()) {
                return false;
            }
        }
        return true;
    }

    private static String separator(final TypeDef def) {
        return def.separator() == null ? "," : def.separator();
    }

    private Pattern pattern(final String name, final String regex) {
        return patterns.computeIfAbsent(name, n -> Pattern.compile(regex));
    }

    private static boolean isInteger(final String v, final Long min, final Long max) {
        try {
            final long l = Long.parseLong(v);
            return (min == null || l >= min) && (max == null || l <= max);
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    private static boolean isUrl(final String v) {
        try {
            final URI uri = new URI(v);
            final String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            return (scheme.equals("http") || scheme.equals("https")) && uri.getHost() != null;
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * @param name e.g. SHA256 or SHA-256
     * @return true if BouncyCastle knows the digest algorithm
     */
    public static boolean isDigestAlgorithm(final String name) {
        try {
            final AlgorithmIdentifier ai = new DefaultDigestAlgorithmIdentifierFinder().find(name);
            if (ai != null && ai.getAlgorithm() != null) {
                return true;
            }
        } catch (RuntimeException ex) { // NOPMD: fall back to the JCA lookup below
        }
        try {
            MessageDigest.getInstance(name, BC);
            return true;
        } catch (NoSuchAlgorithmException ex) {
            return false;
        }
    }

    /**
     * @param name e.g. SHA256withRSA or NONEwithRSA
     * @return true if BouncyCastle knows the signature algorithm
     */
    public static boolean isSignatureAlgorithm(final String name) {
        try {
            if (new DefaultSignatureAlgorithmIdentifierFinder().find(name) != null) {
                return true;
            }
        } catch (RuntimeException ex) { // NOPMD: fall back to the JCA lookup below
        }
        try {
            Signature.getInstance(name, BC);
            return true;
        } catch (NoSuchAlgorithmException ex) {
            return false;
        }
    }

    /**
     * Normalizes a digest algorithm name so that SHA256, sha-256 and SHA-256
     * compare equal.
     */
    public static String normalizeDigest(final String name) {
        return name.trim().toUpperCase(Locale.ROOT).replace("-", "");
    }
}
