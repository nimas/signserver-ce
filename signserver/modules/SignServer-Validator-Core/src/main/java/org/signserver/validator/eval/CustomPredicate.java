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

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Escape hatch for logic the predicate language can not express. A rule
 * uses it as {@code custom: { check: <id>, ...params }}. Implementations are
 * registered with META-INF/services/org.signserver.validator.eval.CustomPredicate.
 *
 * @version $Id$
 */
public interface CustomPredicate {

    /** @return the id used in "check:" */
    String id();

    /**
     * @param params the whole "custom" object, including "check"
     * @param ctx what can be looked at
     * @return the result
     */
    Tri evaluate(JsonNode params, EvalContext ctx);
}
