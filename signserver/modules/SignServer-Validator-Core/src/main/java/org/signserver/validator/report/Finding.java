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

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * One problem (or notice) found by the validator.
 *
 * @param severity ERROR, WARNING or INFO
 * @param code stable machine-readable code, e.g. PROP_WRONG_WORKER or RULE_CSH-1
 * @param message human-readable explanation
 * @param property worker property concerned, if any
 * @param option signclient option concerned (without dash), if any
 * @param suggestion how to fix it, if known
 * @param ruleSource catalog file the finding comes from, if any
 * @version $Id$
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Finding(Severity severity, String code, String message,
        String property, String option, String suggestion,
        String ruleSource) {

    public static Finding of(final Severity severity, final String code,
            final String message) {
        return new Finding(severity, code, message, null, null, null, null);
    }

    public Finding withProperty(final String value) {
        return new Finding(severity, code, message, value, option, suggestion, ruleSource);
    }

    public Finding withOption(final String value) {
        return new Finding(severity, code, message, property, value, suggestion, ruleSource);
    }

    public Finding withSuggestion(final String value) {
        return new Finding(severity, code, message, property, option, value, ruleSource);
    }

    public Finding withRuleSource(final String value) {
        return new Finding(severity, code, message, property, option, suggestion, value);
    }

    /**
     * @return "CODE:property" or "CODE:option" (or just "CODE"), the form used
     * by the golden tests
     */
    public String key() {
        if (property != null && option == null) {
            return code + ":" + property;
        }
        return option != null ? code + ":" + option : code;
    }
}
