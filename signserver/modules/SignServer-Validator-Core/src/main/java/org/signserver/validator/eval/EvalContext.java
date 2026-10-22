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

import java.util.Map;
import org.signserver.validator.WorkerDirectory;
import org.signserver.validator.catalog.ResolvedWorker;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.cli.ParsedCommand;

/**
 * What a predicate can look at. Any part may be null; predicates needing a
 * missing part evaluate to UNKNOWN.
 *
 * @param config worker configuration with upper-case keys
 * @param worker what the catalog says about the worker
 * @param cli the parsed signclient command
 * @param directory other workers
 * @param catalog the rule catalog
 * @version $Id$
 */
public record EvalContext(Map<String, String> config, ResolvedWorker worker,
        ParsedCommand cli, WorkerDirectory directory, RuleCatalog catalog) {

    /** @return the configured value, or null when not set or blank */
    public String value(final String property) {
        if (config == null) {
            return null;
        }
        final String v = config.get(property.toUpperCase());
        return v == null || v.trim().isEmpty() ? null : v.trim();
    }

    /** @return the configured value, else the catalog default, else null */
    public String effective(final String property) {
        final String v = value(property);
        if (v != null || worker == null) {
            return v;
        }
        return worker.property(property.toUpperCase())
                .map(p -> p.spec().defaultValue()).orElse(null);
    }
}
