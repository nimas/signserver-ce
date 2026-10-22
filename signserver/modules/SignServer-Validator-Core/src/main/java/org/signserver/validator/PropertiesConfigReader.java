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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads worker configurations from a properties file in the formats used by
 * SignServer: "signserver setproperties"/"dumpproperties" files with
 * WORKER&lt;id&gt;. or WORKERGENID&lt;n&gt;. prefixes (as in doc/sample-configs), or
 * a plain file with the properties of one worker and no prefix.
 * GLOB., NODE. and removal ("-") entries are ignored.
 *
 * @version $Id$
 */
public final class PropertiesConfigReader {

    private static final Pattern WORKER_KEY = Pattern.compile("(?i)(?:WORKER|SIGNER)(GENID)?(\\d+)\\.(.+)");

    /** One worker of the file. */
    public record Entry(String key, Integer workerId, Map<String, String> config) {

        /** @return the NAME property or null */
        public String name() {
            final String n = config.get("NAME");
            return n == null || n.isBlank() ? null : n.trim();
        }
    }

    private PropertiesConfigReader() {
    }

    /**
     * @param in properties file content
     * @return the workers in the file, in order of first appearance
     */
    public static List<Entry> read(final InputStream in) throws IOException {
        final Properties props = new Properties();
        props.load(in);
        final Map<String, Map<String, String>> byKey = new LinkedHashMap<>();
        final Map<String, Integer> ids = new LinkedHashMap<>();
        for (String rawKey : new TreeSet<>(props.stringPropertyNames())) {
            final String key = rawKey.trim();
            final String upper = key.toUpperCase(Locale.ROOT);
            if (key.startsWith("-") || upper.startsWith("GLOB.") || upper.startsWith("NODE.")) {
                continue;
            }
            final Matcher m = WORKER_KEY.matcher(key);
            final String workerKey;
            final String property;
            if (m.matches()) {
                workerKey = (m.group(1) != null ? "WORKERGENID" : "WORKER") + m.group(2);
                property = m.group(3);
                if (m.group(1) == null) {
                    ids.put(workerKey, Integer.valueOf(m.group(2)));
                }
            } else {
                workerKey = "";
                property = key;
            }
            byKey.computeIfAbsent(workerKey, k -> new LinkedHashMap<>())
                    .put(property.toUpperCase(Locale.ROOT), props.getProperty(rawKey).trim());
        }
        final List<Entry> result = new ArrayList<>();
        byKey.forEach((k, v) -> result.add(new Entry(k, ids.get(k), v)));
        return result;
    }

    /**
     * @param entries workers of a file
     * @param selector worker ID, name, or file key (e.g. WORKERGENID1); null
     * selects the only worker
     * @return the selected worker
     */
    public static Optional<Entry> select(final List<Entry> entries, final String selector) {
        if (selector == null) {
            return entries.size() == 1 ? Optional.of(entries.get(0)) : Optional.empty();
        }
        final String s = selector.trim();
        return entries.stream().filter(e -> s.equalsIgnoreCase(e.name())
                || s.equalsIgnoreCase(e.key())
                || (e.workerId() != null && s.equals(e.workerId().toString())))
                .findFirst();
    }
}
