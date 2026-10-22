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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.signserver.validator.catalog.CatalogModel.OptionSpec;
import org.signserver.validator.catalog.ResolvedCommand;

/**
 * A signclient command line split into command, options and leftovers.
 *
 * @param spec the catalog command, or null when the command is unknown
 * @param command the command name as typed
 * @param options option name (without dash) to the values given, in order
 * @param positionals arguments that belong to no option
 * @version $Id$
 */
public record ParsedCommand(ResolvedCommand spec, String command,
        Map<String, List<String>> options, List<String> positionals) {

    public boolean hasOption(final String name) {
        return options.containsKey(name);
    }

    /** @return the first value of the option, or null */
    public String value(final String name) {
        final List<String> v = options.get(name);
        return v == null || v.isEmpty() ? null : v.get(0);
    }

    /** @return all values of the option (empty if not given) */
    public List<String> values(final String name) {
        return options.getOrDefault(name, Collections.emptyList());
    }

    /** @return the value given, else the option's default from the catalog, else null */
    public String effectiveValue(final String name) {
        final String v = value(name);
        if (v != null || spec == null) {
            return v;
        }
        final OptionSpec o = spec.options().get(name);
        return o == null ? null : o.defaultValue();
    }

    /** @return true if the option's value must not be shown in reports */
    public boolean isSensitive(final String name) {
        final OptionSpec o = spec == null ? null : spec.options().get(name);
        return o != null && Boolean.TRUE.equals(o.sensitive());
    }
}
