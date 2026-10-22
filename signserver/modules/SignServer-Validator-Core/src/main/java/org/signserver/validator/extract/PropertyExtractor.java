package org.signserver.validator.extract;

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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic extraction of property and option names from Java sources:
 * String constants and string literals passed to getProperty(...) or used to
 * create commons-cli options. It is intentionally simple (regular
 * expressions, no compilation) so it runs on any checkout; the catalog
 * lists constants it should ignore.
 *
 * @version $Id$
 */
public final class PropertyExtractor {

    private static final Pattern STRING_CONSTANT = Pattern.compile(
            "static\\s+final\\s+String\\s+(\\w+)\\s*=\\s*\"([^\"]*)\"");
    private static final Pattern GET_PROPERTY_LITERAL = Pattern.compile(
            "getProperty\\w*\\(\\s*\"([^\"]+)\"");
    private static final Pattern OPTION_LITERAL = Pattern.compile(
            "(?:OptionBuilder\\.create|new\\s+Option)\\(\\s*\"([^\"]+)\"");
    private static final Pattern PROPERTY_NAME = Pattern.compile("[A-Z][A-Z0-9_]{2,}");
    private static final Pattern OPTION_NAME = Pattern.compile("[a-z][a-z0-9]{1,}");

    private PropertyExtractor() {
    }

    /**
     * @param source Java source file
     * @return upper-case property names found (constant values and getProperty literals)
     */
    public static Set<String> propertyNames(final Path source) throws IOException {
        final String code = read(source);
        final Set<String> names = new TreeSet<>();
        final Matcher m = STRING_CONSTANT.matcher(code);
        while (m.find()) {
            final String field = m.group(1);
            final String value = m.group(2);
            // Skip default values such as DEFAULTDIGESTALGORITHM = "SHA256",
            // but keep DEFAULTKEY = "DEFAULTKEY"
            final boolean defaultValue = field.contains("DEFAULT") && !field.endsWith(value);
            if (PROPERTY_NAME.matcher(value).matches() && !defaultValue) {
                names.add(value);
            }
        }
        final Matcher g = GET_PROPERTY_LITERAL.matcher(code);
        while (g.find()) {
            if (PROPERTY_NAME.matcher(g.group(1)).matches()) {
                names.add(g.group(1));
            }
        }
        return names;
    }

    /**
     * @param source Java source file of a signclient command
     * @return lower-case option names found (constant values and option literals)
     */
    public static Set<String> optionNames(final Path source) throws IOException {
        final String code = read(source);
        final Set<String> names = new TreeSet<>();
        final Matcher m = STRING_CONSTANT.matcher(code);
        while (m.find()) {
            final String field = m.group(1);
            if (OPTION_NAME.matcher(m.group(2)).matches() && field.equals(field.toUpperCase())
                    && !field.startsWith("DEFAULT") && !field.endsWith("_DESCRIPTION")) {
                names.add(m.group(2));
            }
        }
        final Matcher o = OPTION_LITERAL.matcher(code);
        while (o.find()) {
            names.add(o.group(1));
        }
        return names;
    }

    private static String read(final Path source) throws IOException {
        final String code = new String(Files.readAllBytes(source), StandardCharsets.UTF_8);
        // Drop block and line comments so commented-out constants are not reported
        return code.replaceAll("(?s)/\\*.*?\\*/", "").replaceAll("(?m)//.*$", "");
    }
}
