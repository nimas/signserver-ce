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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.signserver.validator.catalog.CatalogModel.GoldenTest;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.catalog.RuleCatalog.SourcedTest;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.ValidationReport;

/**
 * Runs the golden test cases of the catalog (validator-rules/tests/*.yaml).
 * Used by the unit tests and by "signserver-validator selftest" so a changed
 * catalog can be checked without building.
 *
 * @version $Id$
 */
public final class GoldenTestRunner {

    /** Outcome of one golden test; problems is empty when it passed. */
    public record Outcome(String name, String file, List<String> problems, ValidationReport report) {
        public boolean passed() {
            return problems.isEmpty();
        }
    }

    private final RuleCatalog catalog;
    private final SignServerValidator validator;

    public GoldenTestRunner(final RuleCatalog catalog) {
        this.catalog = catalog;
        this.validator = new SignServerValidator(catalog);
    }

    public List<Outcome> runAll() {
        final Map<String, GoldenTest> byName = new LinkedHashMap<>();
        catalog.getTests().forEach(t -> byName.put(t.test().name(), t.test()));
        final List<Outcome> outcomes = new ArrayList<>();
        for (SourcedTest st : catalog.getTests()) {
            outcomes.add(run(st, byName));
        }
        return outcomes;
    }

    private Outcome run(final SourcedTest st, final Map<String, GoldenTest> byName) {
        final GoldenTest t = st.test();
        Map<String, String> config = null;
        List<Map<String, String>> others = null;
        String cli = t.cli();
        // Inherit config, other workers and command from the extended tests
        final List<GoldenTest> chain = new ArrayList<>();
        for (GoldenTest cur = t; cur != null; cur = cur.extendsTest() == null ? null : byName.get(cur.extendsTest())) {
            if (chain.contains(cur)) {
                break;
            }
            chain.add(0, cur);
        }
        for (GoldenTest g : chain) {
            if (g.config() != null) {
                config = config == null ? new LinkedHashMap<>() : config;
                config.putAll(g.config());
            }
            if (g.otherWorkers() != null) {
                others = g.otherWorkers();
            }
            if (cli == null && g.cli() != null) {
                cli = g.cli();
            }
        }
        final WorkerDirectory directory = others == null ? null
                : WorkerDirectory.of(others.stream().map(SignServerValidator::normalize).toList(), true);

        final List<String> problems = new ArrayList<>();
        final ValidationReport report;
        try {
            report = validator.validate(new ValidationRequest(config, cli, directory, null, "golden test",
                    Boolean.TRUE.equals(t.strict())));
        } catch (RuntimeException ex) {
            problems.add("validation threw " + ex);
            return new Outcome(t.name(), st.file(), problems, null);
        }
        final List<Finding> findings = report.allFindings();
        if (t.expectPassed() != null && t.expectPassed() != report.passed()) {
            problems.add("expected passed=" + t.expectPassed() + " but was " + report.passed());
        }
        for (String expected : nullSafe(t.expectCodes())) {
            if (findings.stream().noneMatch(f -> matches(f, expected))) {
                problems.add("expected finding " + expected + " not reported");
            }
        }
        for (String forbidden : nullSafe(t.forbidCodes())) {
            if (findings.stream().anyMatch(f -> matches(f, forbidden))) {
                problems.add("finding " + forbidden + " must not be reported");
            }
        }
        if (!problems.isEmpty()) {
            problems.add("reported: " + findings.stream().map(f -> f.severity() + " " + f.key())
                    .collect(Collectors.joining(", ")));
        }
        return new Outcome(t.name(), st.file(), problems, report);
    }

    /** "CODE" matches the code; "CODE:X" also requires X to be the property or option. */
    static boolean matches(final Finding f, final String expected) {
        final int colon = expected.indexOf(':');
        final String code = colon < 0 ? expected : expected.substring(0, colon);
        if (!f.code().equals(code)) {
            return false;
        }
        if (colon < 0) {
            return true;
        }
        final String target = expected.substring(colon + 1);
        return target.equals(f.property()) || target.equals(f.option());
    }

    private static List<String> nullSafe(final List<String> l) {
        return l == null ? List.of() : l;
    }
}
