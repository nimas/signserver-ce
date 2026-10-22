package org.signserver.validator.catalog;

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

/**
 * The rule catalog could not be read or is inconsistent. Carries every
 * problem found so that a person (or an AI) can fix them all at once.
 *
 * @version $Id$
 */
public class CatalogException extends Exception {

    private static final long serialVersionUID = 1L;

    private final List<String> problems;

    public CatalogException(final List<String> problems) {
        super("Invalid rule catalog:\n  - " + String.join("\n  - ", problems));
        this.problems = Collections.unmodifiableList(problems);
    }

    public CatalogException(final String message, final Throwable cause) {
        super(message, cause);
        this.problems = Collections.singletonList(message);
    }

    public List<String> getProblems() {
        return problems;
    }
}
