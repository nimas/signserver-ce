package org.signserver.validator.cli;

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
import java.util.List;

/**
 * Splits a command line the way a POSIX shell would for the common cases:
 * whitespace separation, 'single' and "double" quotes, backslash escapes and
 * backslash-newline continuations. No variable or glob expansion.
 *
 * @version $Id$
 */
public final class CommandLineTokenizer {

    private CommandLineTokenizer() {
    }

    /**
     * @param line the command line
     * @return the arguments
     * @throws IllegalArgumentException if a quote is not closed
     */
    public static List<String> tokenize(final String line) {
        final List<String> tokens = new ArrayList<>();
        final StringBuilder current = new StringBuilder();
        boolean inToken = false;
        char quote = 0;
        for (int i = 0; i < line.length(); i++) {
            final char c = line.charAt(i);
            if (quote == '\'') {
                if (c == '\'') {
                    quote = 0;
                } else {
                    current.append(c);
                }
            } else if (quote == '"') {
                if (c == '"') {
                    quote = 0;
                } else if (c == '\\' && i + 1 < line.length()
                        && "\"\\$`\n".indexOf(line.charAt(i + 1)) >= 0) {
                    i++;
                    if (line.charAt(i) != '\n') {
                        current.append(line.charAt(i));
                    }
                } else {
                    current.append(c);
                }
            } else if (c == '\'' || c == '"') {
                quote = c;
                inToken = true;
            } else if (c == '\\' && i + 1 < line.length()) {
                i++;
                if (line.charAt(i) != '\n' && line.charAt(i) != '\r') {
                    current.append(line.charAt(i));
                    inToken = true;
                }
            } else if (Character.isWhitespace(c)) {
                if (inToken) {
                    tokens.add(current.toString());
                    current.setLength(0);
                    inToken = false;
                }
            } else {
                current.append(c);
                inToken = true;
            }
        }
        if (quote != 0) {
            throw new IllegalArgumentException("Unterminated " + (quote == '"' ? "double" : "single") + " quote");
        }
        if (inToken) {
            tokens.add(current.toString());
        }
        return tokens;
    }
}
