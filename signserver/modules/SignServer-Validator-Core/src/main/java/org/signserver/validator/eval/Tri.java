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

/**
 * Three-valued result of a predicate. UNKNOWN is used when the information
 * needed is not available, e.g. a rule about another worker when only one
 * configuration file was given.
 *
 * @version $Id$
 */
public enum Tri {
    TRUE,
    FALSE,
    UNKNOWN;

    public static Tri of(final boolean value) {
        return value ? TRUE : FALSE;
    }

    public Tri not() {
        return this == UNKNOWN ? UNKNOWN : (this == TRUE ? FALSE : TRUE);
    }
}
