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
package org.signserver.admin.web.ejb;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.log.AdminInfo;
import org.signserver.validator.SignServerValidator;
import org.signserver.validator.ValidationRequest;
import org.signserver.validator.WorkerDirectory;
import org.signserver.validator.catalog.CatalogException;
import org.signserver.validator.catalog.CatalogSource;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.report.ValidationReport;

/**
 * Runs the SignServer Validator on a worker of this server, reading the
 * configurations through the local worker session.
 *
 * <p>The rule catalog embedded in the validator jar is used, unless the
 * system property signserver.validator.rules names a catalog directory
 * (so rules can be updated without redeploying).</p>
 *
 * @version $Id$
 */
final class WorkerValidation {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerValidation.class);

    /** System property with a catalog directory overriding the embedded one. */
    static final String RULES_PROPERTY = "signserver.validator.rules";

    private static SignServerValidator validator;
    private static String loadedFrom;

    private WorkerValidation() {
    }

    /**
     * @return the validator, loading the catalog on first use or when the
     * catalog location changed
     */
    static synchronized SignServerValidator validator() throws CatalogException {
        final String dir = System.getProperty(RULES_PROPERTY);
        final String location = dir == null || dir.isBlank() ? "embedded" : dir;
        if (validator == null || !location.equals(loadedFrom)) {
            final CatalogSource source = dir == null || dir.isBlank()
                    ? CatalogSource.embedded() : CatalogSource.directory(Path.of(dir));
            validator = new SignServerValidator(RuleCatalog.load(source));
            loadedFrom = location;
            LOG.info("Loaded validator rule catalog " + validator.getCatalog().getCatalogVersion() + " from " + location);
        }
        return validator;
    }

    /**
     * @param worker local worker session
     * @param adminInfo the administrator
     * @param workerId worker to validate
     * @param cli optional signclient command line to validate with it
     * @return the report
     * @throws CatalogException if the rule catalog is broken
     */
    static ValidationReport validate(final WorkerSessionLocal worker, final AdminInfo adminInfo,
            final int workerId, final String cli) throws CatalogException {
        final Map<String, String> config = configOf(worker, adminInfo, workerId);
        final WorkerDirectory directory = new WorkerDirectory() {
            @Override
            public Optional<Map<String, String>> find(final String idOrName) {
                final String s = idOrName.trim();
                int id;
                try {
                    id = s.matches("\\d+") ? Integer.parseInt(s) : worker.getWorkerId(s);
                } catch (InvalidWorkerIdException ex) {
                    return Optional.empty();
                }
                if (id == 0 || !worker.getAllWorkers().contains(id)) {
                    return Optional.empty();
                }
                return Optional.of(configOf(worker, adminInfo, id));
            }

            @Override
            public boolean isComplete() {
                return true;
            }
        };
        final String command = cli == null || cli.isBlank() ? null : cli.trim();
        return validator().validate(new ValidationRequest(config, command, directory, workerId,
                "Admin Web", false));
    }

    /**
     * The worker configuration with the values of sensitive properties (as
     * configured at deploy time) replaced by the mask placeholder, so they
     * count as set but are never handed to the validator.
     */
    private static Map<String, String> configOf(final WorkerSessionLocal worker,
            final AdminInfo adminInfo, final int workerId) {
        final WorkerConfig wc = worker.getCurrentWorkerConfig(adminInfo, workerId);
        final Properties props = wc.getProperties();
        final Map<String, String> config = new LinkedHashMap<>();
        for (String key : props.stringPropertyNames()) {
            config.put(key, wc.shouldMaskProperty(key)
                    ? WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER : props.getProperty(key));
        }
        config.put(WorkerDirectory.WORKERID_KEY, Integer.toString(workerId));
        return config;
    }
}
