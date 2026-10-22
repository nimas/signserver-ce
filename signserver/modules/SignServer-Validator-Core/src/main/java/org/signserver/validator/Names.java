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

import java.util.Collection;
import java.util.Locale;
import java.util.Optional;

/**
 * Helpers for "did you mean" suggestions and for showing values safely.
 *
 * @version $Id$
 */
public final class Names {

    /** Values longer than this are shortened in messages. */
    private static final int MAX_SHOWN = 60;

    private Names() {
    }

    /**
     * @param input what was typed
     * @param candidates known names
     * @return the closest candidate when it is close enough to be a likely typo
     */
    public static Optional<String> closest(final String input, final Collection<String> candidates) {
        final String in = input.toLowerCase(Locale.ROOT);
        String best = null;
        int bestDistance = Integer.MAX_VALUE;
        for (String c : candidates) {
            final int d = distance(in, c.toLowerCase(Locale.ROOT));
            if (d < bestDistance) {
                best = c;
                bestDistance = d;
            }
        }
        final int allowed = Math.max(1, Math.min(3, input.length() / 4));
        return best != null && bestDistance <= allowed ? Optional.of(best) : Optional.empty();
    }

    /** Levenshtein distance. */
    static int distance(final String a, final String b) {
        final int[] prev = new int[b.length() + 1];
        final int[] cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                final int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            System.arraycopy(cur, 0, prev, 0, cur.length);
        }
        return prev[b.length()];
    }

    /**
     * @param value value to show
     * @param sensitive whether to hide it
     * @return the value for use in a message
     */
    public static String show(final String value, final boolean sensitive) {
        if (value == null) {
            return "";
        }
        if (sensitive) {
            return "******";
        }
        return value.length() > MAX_SHOWN ? value.substring(0, MAX_SHOWN) + "..." : value;
    }
}
