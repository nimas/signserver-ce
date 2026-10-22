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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Result of a validation, serialized as the JSON report.
 *
 * @version $Id$
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"validatorVersion", "catalogVersion", "target", "passed",
    "strict", "summary", "sections"})
public record ValidationReport(String validatorVersion, String catalogVersion,
        Target target, boolean passed, boolean strict, Summary summary,
        Sections sections) {

    /** What was validated. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Target(Integer workerId, String workerName,
            String implementationClass, String workerType, String command,
            String configSource) {
    }

    /** Number of findings per severity. */
    public record Summary(int errors, int warnings, int infos) {
    }

    /** Findings per part of the validation; null when the part did not run. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Sections(List<Finding> config, List<Finding> cli,
            List<Finding> combination) {
    }

    /**
     * Builds a report and computes passed/summary from the findings.
     *
     * @param config config findings or null when no configuration was given
     * @param cli CLI findings or null when no command was given
     * @param combination combination findings or null when not both were given
     */
    public static ValidationReport create(final String validatorVersion,
            final String catalogVersion, final Target target,
            final boolean strict, final List<Finding> config,
            final List<Finding> cli, final List<Finding> combination) {
        final List<Finding> all = new ArrayList<>();
        Stream.of(config, cli, combination).filter(l -> l != null).forEach(all::addAll);
        final int errors = (int) all.stream().filter(f -> f.severity() == Severity.ERROR).count();
        final int warnings = (int) all.stream().filter(f -> f.severity() == Severity.WARNING).count();
        final int infos = all.size() - errors - warnings;
        final boolean passed = errors == 0 && (!strict || warnings == 0);
        return new ValidationReport(validatorVersion, catalogVersion, target,
                passed, strict, new Summary(errors, warnings, infos),
                new Sections(config, cli, combination));
    }

    /** @return all findings of all sections */
    @JsonIgnore
    public List<Finding> allFindings() {
        final List<Finding> all = new ArrayList<>();
        Stream.of(sections.config(), sections.cli(), sections.combination())
                .filter(l -> l != null).forEach(all::addAll);
        return all;
    }
}
