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
package org.signserver.admin.web;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import jakarta.ejb.EJB;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.apache.log4j.Logger;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.auth.LoginBean;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.validator.catalog.CatalogException;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.ReportFormatter;
import org.signserver.validator.report.ValidationReport;

/**
 * Backing bean for the "Validate" section of the worker configuration page.
 *
 * @version $Id$
 */
@Named
@ViewScoped
public class WorkerValidationBean implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerValidationBean.class);

    /** One row of the findings table (plain strings, so the view state serializes). */
    public static class Row implements Serializable {
        private static final long serialVersionUID = 1L;

        private final String section;
        private final String severity;
        private final String code;
        private final String target;
        private final String message;
        private final String suggestion;

        Row(final String section, final Finding finding) {
            this.section = section;
            this.severity = finding.severity().name();
            this.code = finding.code();
            final StringBuilder sb = new StringBuilder();
            if (finding.property() != null) {
                sb.append(finding.property());
            }
            if (finding.option() != null) {
                sb.append(sb.length() > 0 ? " / " : "").append('-').append(finding.option());
            }
            this.target = sb.toString();
            this.message = finding.message();
            this.suggestion = finding.suggestion();
        }

        public String getSection() {
            return section;
        }

        public String getSeverity() {
            return severity;
        }

        public String getCode() {
            return code;
        }

        /** @return the property and/or option the finding is about */
        public String getTarget() {
            return target;
        }

        public String getMessage() {
            return message;
        }

        public String getSuggestion() {
            return suggestion;
        }

        /** @return existing Admin Web CSS class for the severity */
        public String getStyleClass() {
            return switch (severity) {
                case "ERROR" -> "errorMessage";
                case "WARNING" -> "warningMessage";
                default -> "";
            };
        }
    }

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @Inject
    private LoginBean loginBean;

    private Integer id;
    private String cli;
    private boolean passed;
    private String summary;
    private String reportJson;
    private List<Row> rows;
    private String error;

    public Integer getId() {
        return id;
    }

    public void setId(final Integer id) {
        this.id = id;
    }

    public String getCli() {
        return cli;
    }

    public void setCli(final String cli) {
        this.cli = cli;
    }

    /** Action of the Validate button: stays on the page. */
    public String validate() throws AdminNotAuthorizedException {
        error = null;
        rows = null;
        reportJson = null;
        if (id == null) {
            error = "No worker selected";
            return null;
        }
        try {
            final ValidationReport report = workerSessionBean.validateWorker(loginBean.getAdminPrincipal(), id, cli);
            final ValidationReport.Summary s = report.summary();
            passed = report.passed();
            summary = s.errors() + " error(s), " + s.warnings() + " warning(s), " + s.infos()
                    + " info. Rule catalog " + report.catalogVersion();
            rows = new ArrayList<>();
            addRows("Configuration", report.sections().config());
            addRows("Command", report.sections().cli());
            addRows("Combination", report.sections().combination());
            reportJson = ReportFormatter.toJson(report);
        } catch (CatalogException ex) {
            LOG.error("Validator rule catalog could not be loaded", ex);
            error = ex.getMessage();
        }
        return null;
    }

    private void addRows(final String section, final List<Finding> findings) {
        if (findings != null) {
            findings.forEach(f -> rows.add(new Row(section, f)));
        }
    }

    public boolean isValidated() {
        return rows != null;
    }

    public boolean isPassed() {
        return passed;
    }

    public List<Row> getRows() {
        return rows;
    }

    public String getSummary() {
        return summary;
    }

    public String getReportJson() {
        return reportJson;
    }

    public String getError() {
        return error;
    }
}
