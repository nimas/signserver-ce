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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.util.List;

/**
 * Renders a validation report as JSON or as text for people.
 *
 * @version $Id$
 */
public final class ReportFormatter {

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private ReportFormatter() {
    }

    public static String toJson(final ValidationReport report) {
        try {
            return JSON.writeValueAsString(report);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Unable to serialize report", ex);
        }
    }

    public static String toText(final ValidationReport report) {
        final StringBuilder sb = new StringBuilder();
        final ValidationReport.Target t = report.target();
        sb.append("SignServer Validator ").append(report.validatorVersion())
                .append(" (rule catalog ").append(report.catalogVersion()).append(")\n");
        if (t != null) {
            if (t.workerName() != null || t.workerId() != null) {
                sb.append("Worker:  ");
                if (t.workerName() != null) {
                    sb.append(t.workerName());
                }
                if (t.workerId() != null) {
                    sb.append(" (id ").append(t.workerId()).append(')');
                }
                if (t.workerType() != null) {
                    sb.append(" [type ").append(t.workerType()).append(']');
                }
                sb.append('\n');
            }
            if (t.configSource() != null) {
                sb.append("Source:  ").append(t.configSource()).append('\n');
            }
            if (t.command() != null) {
                sb.append("Command: ").append(t.command()).append('\n');
            }
        }
        final ValidationReport.Sections s = report.sections();
        appendSection(sb, "Configuration", s.config());
        appendSection(sb, "CLI command", s.cli());
        appendSection(sb, "Command + worker combination", s.combination());
        final ValidationReport.Summary sum = report.summary();
        sb.append('\n').append(report.passed() ? "RESULT: PASSED" : "RESULT: FAILED")
                .append(" (").append(sum.errors()).append(" error(s), ")
                .append(sum.warnings()).append(" warning(s), ")
                .append(sum.infos()).append(" info)")
                .append(report.strict() ? " [strict]" : "").append('\n');
        return sb.toString();
    }

    private static void appendSection(final StringBuilder sb, final String title,
            final List<Finding> findings) {
        if (findings == null) {
            return;
        }
        sb.append('\n').append(title).append(": ");
        if (findings.isEmpty()) {
            sb.append("OK\n");
            return;
        }
        sb.append(findings.size()).append(" finding(s)\n");
        for (Finding f : findings) {
            sb.append("  [").append(f.severity()).append("] ").append(f.code());
            if (f.property() != null) {
                sb.append(" ").append(f.property());
            }
            if (f.option() != null) {
                sb.append(" -").append(f.option());
            }
            sb.append(": ").append(f.message()).append('\n');
            if (f.suggestion() != null) {
                sb.append("      hint: ").append(f.suggestion()).append('\n');
            }
        }
    }
}
