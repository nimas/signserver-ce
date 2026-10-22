package org.signserver.validator.extract;

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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.signserver.validator.catalog.CatalogModel.CliOptionGroupFile;
import org.signserver.validator.catalog.CatalogModel.ExtractionSpec;
import org.signserver.validator.catalog.CatalogModel.WorkerFile;
import org.signserver.validator.catalog.ResolvedCommand;
import org.signserver.validator.catalog.RuleCatalog;

/**
 * Compares the catalog with the SignServer sources it was written from
 * (the "extraction" section of worker and CLI files) and reports drift:
 * names in the code that the catalog does not know, and names declared in
 * the catalog that are no longer in the code. The report is the starting
 * point for updating the catalog, by hand or with AI.
 *
 * @version $Id$
 */
public final class DriftChecker {

    /** Drift of one catalog file. */
    public record Entry(String catalogFile, List<String> sources,
            Set<String> missingInCatalog, Set<String> notFoundInCode,
            List<String> errors) {

        public boolean hasDrift() {
            return !missingInCatalog.isEmpty() || !notFoundInCode.isEmpty() || !errors.isEmpty();
        }
    }

    private final RuleCatalog catalog;
    private final Path signserverHome;

    /**
     * @param catalog the catalog
     * @param signserverHome the signserver directory (sources are relative to it)
     */
    public DriftChecker(final RuleCatalog catalog, final Path signserverHome) {
        this.catalog = catalog;
        this.signserverHome = signserverHome;
    }

    public List<Entry> check() {
        final List<Entry> entries = new ArrayList<>();
        for (WorkerFile w : catalog.getWorkers().values()) {
            if (w.extraction() != null) {
                entries.add(checkWorker(w));
            }
        }
        for (ResolvedCommand c : catalog.getCommands().values()) {
            final ExtractionSpec ex = commandExtraction(c);
            if (ex != null) {
                final Set<String> own = new TreeSet<>(c.options().keySet());
                // options coming from option groups are checked with the group
                catalog.getOptionGroups().values().forEach(g -> own.removeAll(g.options().keySet()));
                final Set<String> known = new TreeSet<>(c.options().keySet());
                known.add(c.command()); // the command name constant, e.g. COMMAND = "signdocument"
                entries.add(compare(c.file(), ex, true, known, own));
            }
        }
        for (CliOptionGroupFile g : catalog.getOptionGroups().values()) {
            if (g.extraction() != null) {
                entries.add(compare(catalog.getOptionGroupFile(g.optionGroup()), g.extraction(), true,
                        g.options().keySet(), g.options().keySet()));
            }
        }
        return entries;
    }

    private ExtractionSpec commandExtraction(final ResolvedCommand c) {
        return catalog.getCliExtraction(c.file());
    }

    private Entry checkWorker(final WorkerFile w) {
        final Set<String> known = catalog.closure(w, true);
        final Set<String> own = new TreeSet<>();
        if (w.properties() != null) {
            w.properties().forEach((name, spec) -> {
                if (!"none".equals(spec.codeRef())) {
                    own.add(name);
                }
            });
        }
        return compare(catalog.getWorkerFile(w.worker()), w.extraction(), false, known, own);
    }

    private Entry compare(final String file, final ExtractionSpec ex, final boolean options,
            final Set<String> known, final Set<String> ownDeclared) {
        final Set<String> inCode = new TreeSet<>();
        final List<String> errors = new ArrayList<>();
        for (String src : ex.sources()) {
            final Path p = signserverHome.resolve(src);
            if (!Files.isRegularFile(p)) {
                errors.add("source not found: " + src);
                continue;
            }
            try {
                inCode.addAll(options ? PropertyExtractor.optionNames(p) : PropertyExtractor.propertyNames(p));
            } catch (IOException e) {
                errors.add("can not read " + src + ": " + e.getMessage());
            }
        }
        if (ex.ignoreConstants() != null) {
            inCode.removeAll(ex.ignoreConstants());
        }
        final Set<String> missing = new TreeSet<>(inCode);
        missing.removeAll(known);
        final Set<String> stale = new TreeSet<>(ownDeclared);
        stale.removeAll(inCode);
        return new Entry(file, ex.sources(), missing, stale, errors);
    }
}
