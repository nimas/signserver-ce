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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.signserver.validator.Names;

/**
 * Expands placeholders in rule messages: ${PROPERTY} (effective value),
 * ${cli:option} (option value) and ${worker} (worker name). Sensitive values
 * are masked.
 *
 * @version $Id$
 */
public final class Messages {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

    private Messages() {
    }

    public static String render(final String template, final EvalContext ctx) {
        if (template == null) {
            return null;
        }
        final Matcher m = PLACEHOLDER.matcher(template);
        final StringBuilder sb = new StringBuilder();
        while (m.find()) {
            final String key = m.group(1);
            final String value;
            if (key.equals("worker")) {
                value = ctx.worker() == null ? "the worker" : ctx.worker().getName();
            } else if (key.startsWith("cli:")) {
                final String opt = key.substring(4);
                value = ctx.cli() == null ? "" : Names.show(ctx.cli().effectiveValue(opt), ctx.cli().isSensitive(opt));
            } else {
                final boolean sensitive = ctx.worker() != null && ctx.worker().isSensitive(key.toUpperCase());
                value = Names.show(ctx.effective(key), sensitive);
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(value));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
