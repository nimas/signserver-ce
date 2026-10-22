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
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Access to the configuration of other workers, for rules that refer to
 * them (e.g. CRYPTOTOKEN must name a crypto worker).
 *
 * @version $Id$
 */
public interface WorkerDirectory {

    /**
     * @param idOrName worker ID or name
     * @return configuration (upper-case keys) of the worker, or empty
     */
    Optional<Map<String, String>> find(String idOrName);

    /**
     * @return true if find() knows every worker of the server, so a missing
     * worker really does not exist; false when only a subset is known (e.g.
     * the workers of one configuration file)
     */
    boolean isComplete();

    /**
     * @param configs configurations with upper-case keys
     * @param complete see {@link #isComplete()}
     * @return directory over the given configurations (matched by NAME or by
     * the WORKERID key when present)
     */
    static WorkerDirectory of(final Collection<Map<String, String>> configs, final boolean complete) {
        final List<Map<String, String>> list = new ArrayList<>(configs);
        return new WorkerDirectory() {
            @Override
            public Optional<Map<String, String>> find(final String idOrName) {
                final String key = idOrName.trim();
                return list.stream().filter(c -> key.equalsIgnoreCase(c.get("NAME"))
                        || key.equals(c.get(WORKERID_KEY))).findFirst();
            }

            @Override
            public boolean isComplete() {
                return complete;
            }
        };
    }

    /**
     * Pseudo property holding the worker ID in configurations handed to a
     * directory; it is never validated as a property.
     */
    String WORKERID_KEY = "__WORKERID__";
}
