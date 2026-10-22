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

import java.util.List;
import java.util.Map;
import org.signserver.validator.catalog.CatalogModel.OptionSpec;
import org.signserver.validator.catalog.ResolvedWorker.SourcedRule;

/**
 * A signclient command with the options of its option groups merged in.
 *
 * @param command command name, e.g. signdocument
 * @param file catalog file of the command
 * @param options all options by name (without dash)
 * @param rules command rules plus option group rules
 * @param targetKinds worker kinds the command can be used with (empty: any)
 * @param workerOptions options naming the target worker, e.g. workername
 * @version $Id$
 */
public record ResolvedCommand(String command, String file,
        Map<String, OptionSpec> options, List<SourcedRule> rules,
        List<String> targetKinds, List<String> workerOptions) {
}
