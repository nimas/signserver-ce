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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Where the catalog files are read from: the copy embedded in the jar, or a
 * directory so rules can be changed without rebuilding.
 *
 * @version $Id$
 */
public interface CatalogSource {

    /** Classpath location of the embedded catalog. */
    String EMBEDDED_ROOT = "validator-rules/";

    /**
     * @param relativePath path relative to the catalog root, e.g. workers/CMSSigner.yaml
     * @return stream of the file
     * @throws IOException if the file does not exist or can not be read
     */
    InputStream open(String relativePath) throws IOException;

    /** @return description of the location, for reports and errors */
    String describe();

    /** @return the catalog embedded in the validator jar */
    static CatalogSource embedded() {
        return new CatalogSource() {
            @Override
            public InputStream open(final String relativePath) throws IOException {
                final InputStream in = CatalogSource.class.getClassLoader()
                        .getResourceAsStream(EMBEDDED_ROOT + relativePath);
                if (in == null) {
                    throw new FileNotFoundException("classpath:" + EMBEDDED_ROOT + relativePath);
                }
                return in;
            }

            @Override
            public String describe() {
                return "embedded";
            }
        };
    }

    /** @return a catalog read from a directory */
    static CatalogSource directory(final Path root) {
        return new CatalogSource() {
            @Override
            public InputStream open(final String relativePath) throws IOException {
                final Path file = root.resolve(relativePath).normalize();
                if (!file.startsWith(root.normalize())) {
                    throw new IOException("Catalog path outside the catalog directory: " + relativePath);
                }
                return Files.newInputStream(file);
            }

            @Override
            public String describe() {
                return root.toString();
            }
        };
    }
}
