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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.validator.catalog.CatalogException;
import org.signserver.validator.catalog.CatalogSource;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.extract.DriftChecker;

/**
 * Checks the rule catalog itself: it loads, every file matches the JSON
 * Schema, all golden test cases pass and it is in sync with the sources.
 * These tests are what makes a catalog change (by a person or by AI) safe.
 *
 * @version $Id$
 */
public class CatalogTest {

    private static Path rulesDir;
    private static Path signserverHome;
    private static RuleCatalog catalog;

    @BeforeClass
    public static void setUpClass() throws Exception {
        rulesDir = Path.of(System.getProperty("validator.rules.dir", "../../validator-rules"));
        signserverHome = Path.of(System.getProperty("signserver.home", "../.."));
        catalog = RuleCatalog.load(CatalogSource.directory(rulesDir));
    }

    @Test
    public void testEmbeddedCatalogLoads() throws Exception {
        final RuleCatalog embedded = RuleCatalog.load(CatalogSource.embedded());
        assertEquals(catalog.getCatalogVersion(), embedded.getCatalogVersion());
        assertTrue(embedded.getWorkers().containsKey("CMSSigner"));
        assertTrue(embedded.getCommands().containsKey("signdocument"));
    }

    @Test
    public void testAllFilesMatchSchema() throws Exception {
        final ObjectMapper json = new ObjectMapper();
        final YAMLMapper yaml = new YAMLMapper();
        final JsonNode schemaRoot = json.readTree(rulesDir.resolve("schema/catalog.schema.json").toFile());
        final JsonNode index = yaml.readTree(rulesDir.resolve("catalog.yaml").toFile());
        final List<String> problems = new ArrayList<>();

        validate(schemaRoot, "indexFile", "catalog.yaml", index, problems);
        validate(schemaRoot, "valueTypesFile", index.get("valueTypes").asText(), null, problems);
        validateAll(schemaRoot, "groupFile", index.get("groups"), problems);
        validateAll(schemaRoot, "workerFile", index.get("workers"), problems);
        validateAll(schemaRoot, "cliOptionGroupFile", index.get("cliOptionGroups"), problems);
        validateAll(schemaRoot, "cliFile", index.get("cli"), problems);
        validate(schemaRoot, "combinationsFile", index.get("combinations").asText(), null, problems);
        validateAll(schemaRoot, "testFile", index.get("tests"), problems);
        if (!problems.isEmpty()) {
            fail("Schema violations:\n" + String.join("\n", problems));
        }
    }

    private static void validateAll(final JsonNode schemaRoot, final String def, final JsonNode files,
            final List<String> problems) throws Exception {
        for (JsonNode f : files) {
            validate(schemaRoot, def, f.asText(), null, problems);
        }
    }

    private static void validate(final JsonNode schemaRoot, final String def, final String file,
            final JsonNode preloaded, final List<String> problems) throws Exception {
        final ObjectNode wrapper = schemaRoot.deepCopy();
        wrapper.put("$ref", "#/$defs/" + def);
        final JsonSchema schema = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012).getSchema(wrapper);
        final JsonNode data = preloaded != null ? preloaded : new YAMLMapper().readTree(rulesDir.resolve(file).toFile());
        final Set<ValidationMessage> errors = schema.validate(data);
        errors.forEach(e -> problems.add(file + ": " + e.getMessage()));
    }

    @Test
    public void testGoldenCases() {
        final List<GoldenTestRunner.Outcome> outcomes = new GoldenTestRunner(catalog).runAll();
        assertFalse("no golden tests found", outcomes.isEmpty());
        final String failures = outcomes.stream().filter(o -> !o.passed())
                .map(o -> o.file() + " / " + o.name() + ":\n    " + String.join("\n    ", o.problems()))
                .collect(Collectors.joining("\n"));
        if (!failures.isEmpty()) {
            fail("Golden test failures:\n" + failures);
        }
    }

    @Test
    public void testNoDriftAgainstSources() {
        final List<DriftChecker.Entry> drift = new DriftChecker(catalog, signserverHome).check()
                .stream().filter(DriftChecker.Entry::hasDrift).toList();
        if (!drift.isEmpty()) {
            fail("The catalog is out of sync with the code (update validator-rules, see README.md):\n"
                    + drift.stream().map(e -> e.catalogFile() + ": missing in catalog " + e.missingInCatalog()
                            + ", not found in code " + e.notFoundInCode() + " " + e.errors())
                            .collect(Collectors.joining("\n")));
        }
    }

    @Test
    public void testBrokenCatalogReportsAllProblems() throws Exception {
        final File dir = java.nio.file.Files.createTempDirectory("broken-rules").toFile();
        java.nio.file.Files.writeString(dir.toPath().resolve("catalog.yaml"),
                "catalogVersion: \"x\"\nvalueTypes: value-types.yaml\ngroups: [g.yaml]\nworkers: [w.yaml]\ncli: []\n");
        java.nio.file.Files.writeString(dir.toPath().resolve("value-types.yaml"),
                "types:\n  string: { kind: string }\n  bad: { kind: nosuchkind }\n");
        java.nio.file.Files.writeString(dir.toPath().resolve("g.yaml"),
                "group: base-worker\nproperties:\n  NAME: { type: missingType }\n");
        java.nio.file.Files.writeString(dir.toPath().resolve("w.yaml"),
                "worker: W\nkind: signer\nmatch: { IMPLEMENTATION_CLASS: a.B }\ninherits: [nogroup]\n"
                + "rules:\n  - id: R-1\n    when: { nosuchpredicate: X }\n    severity: ERROR\n    message: m\n");
        try {
            RuleCatalog.load(CatalogSource.directory(dir.toPath()));
            fail("broken catalog accepted");
        } catch (CatalogException ex) {
            final String all = String.join("\n", ex.getProblems());
            assertTrue(all, all.contains("unknown kind 'nosuchkind'"));
            assertTrue(all, all.contains("unknown type 'missingType'"));
            assertTrue(all, all.contains("unknown group 'nogroup'"));
            assertTrue(all, all.contains("unknown predicate 'nosuchpredicate'"));
        }
    }
}
