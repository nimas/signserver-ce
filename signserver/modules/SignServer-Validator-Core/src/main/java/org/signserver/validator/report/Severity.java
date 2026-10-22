package org.signserver.validator.report;

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
 * Severity of a finding. Only ERROR makes a validation fail (WARNING too in
 * strict mode).
 *
 * @version $Id$
 */
public enum Severity {
    ERROR,
    WARNING,
    INFO;

    /**
     * @param value ERROR, WARNING or INFO (case-insensitive)
     * @param defaultValue returned when value is null
     * @return the severity
     */
    public static Severity parse(final String value, final Severity defaultValue) {
        return value == null ? defaultValue : Severity.valueOf(value.trim().toUpperCase());
    }
}
