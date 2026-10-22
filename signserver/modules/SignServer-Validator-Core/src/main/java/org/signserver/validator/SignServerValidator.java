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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.signserver.validator.catalog.CatalogException;
import org.signserver.validator.catalog.CatalogSource;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.ValidationReport;

/**
 * Entry point of the validator: validates a worker configuration, a
 * signclient command, or both together.
 *
 * <pre>
 * SignServerValidator v = SignServerValidator.withEmbeddedCatalog();
 * ValidationReport r = v.validate(new ValidationRequest(config, "signclient signdocument ...", null, 5, "REST", false));
 * </pre>
 *
 * @version $Id$
 */
public final class SignServerValidator {

    /** Version of the validator engine. */
    public static final String VERSION = "1.0";

    private final RuleCatalog catalog;
    private final ConfigValidator configValidator;
    private final CliValidator cliValidator;
    private final CombinationValidator combinationValidator;

    public SignServerValidator(final RuleCatalog catalog) {
        this.catalog = catalog;
        this.configValidator = new ConfigValidator(catalog);
        this.cliValidator = new CliValidator(catalog);
        this.combinationValidator = new CombinationValidator(catalog);
    }

    /** @return a validator using the rule catalog embedded in the jar */
    public static SignServerValidator withEmbeddedCatalog() throws CatalogException {
        return new SignServerValidator(RuleCatalog.load(CatalogSource.embedded()));
    }

    public RuleCatalog getCatalog() {
        return catalog;
    }

    /**
     * @param config configuration with keys in any case
     * @return a copy with upper-case keys (as SignServer stores them)
     */
    public static Map<String, String> normalize(final Map<String, String> config) {
        final Map<String, String> result = new LinkedHashMap<>();
        config.forEach((k, v) -> result.put(k.startsWith("__") ? k : k.trim().toUpperCase(Locale.ROOT),
                v == null ? "" : v));
        return result;
    }

    public ValidationReport validate(final ValidationRequest request) {
        if (request.config() == null && request.cli() == null) {
            throw new IllegalArgumentException("Nothing to validate: give a configuration and/or a command");
        }
        Map<String, String> config = null;
        ConfigValidator.Result configResult = null;
        if (request.config() != null) {
            config = normalize(request.config());
            if (request.workerId() != null) {
                config.put(WorkerDirectory.WORKERID_KEY, request.workerId().toString());
            }
            configResult = configValidator.validate(config, request.directory());
        }
        CliValidator.Result cliResult = null;
        if (request.cli() != null) {
            cliResult = cliValidator.validate(request.cli());
        }
        List<Finding> combination = null;
        if (configResult != null && cliResult != null && cliResult.parsed() != null
                && cliResult.parsed().spec() != null) {
            combination = combinationValidator.validate(config, configResult.worker(),
                    cliResult.parsed(), request.directory());
        }

        final ValidationReport.Target target = new ValidationReport.Target(
                request.workerId(),
                config == null ? null : emptyToNull(config.get("NAME")),
                config == null ? null : emptyToNull(config.get("IMPLEMENTATION_CLASS")),
                configResult == null ? null : configResult.worker().getName(),
                cliResult == null || cliResult.parsed() == null ? null : cliResult.parsed().command(),
                request.configSource());
        return ValidationReport.create(VERSION, catalog.getCatalogVersion(), target,
                request.strict(),
                configResult == null ? null : configResult.findings(),
                cliResult == null ? null : cliResult.findings(),
                combination);
    }

    private static String emptyToNull(final String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
