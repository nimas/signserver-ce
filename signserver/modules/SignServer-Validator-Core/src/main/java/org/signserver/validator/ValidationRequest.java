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

import java.util.Map;

/**
 * What to validate. At least one of config and cli must be given; both
 * gives the combination check too.
 *
 * @param config worker configuration (keys are upper-cased), or null
 * @param cli signclient command line, or null
 * @param directory other workers for cross-worker rules, or null
 * @param workerId ID of the worker, if known
 * @param configSource where the configuration came from, for the report
 * @param strict whether warnings also make the validation fail
 * @version $Id$
 */
public record ValidationRequest(Map<String, String> config, String cli,
        WorkerDirectory directory, Integer workerId, String configSource,
        boolean strict) {
}
