package org.signserver.validator.eval;

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
import org.signserver.validator.catalog.CatalogModel.RuleSpec;
import org.signserver.validator.catalog.ResolvedWorker.SourcedRule;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.Severity;

/**
 * Evaluates catalog rules. A rule produces a finding when "when" holds (or
 * is absent) and "require" does not hold (or is absent). When the outcome
 * depends on information that is not available, ERROR and WARNING rules
 * produce an INFO NOT_VERIFIED finding instead.
 *
 * @version $Id$
 */
public final class RuleRunner {

    /** Code of findings for rules that could not be evaluated. */
    public static final String NOT_VERIFIED = "NOT_VERIFIED";

    private RuleRunner() {
    }

    public static void run(final List<SourcedRule> rules, final EvalContext ctx,
            final List<Finding> out) {
        for (SourcedRule sr : rules) {
            final RuleSpec r = sr.rule();
            final Tri when = r.when() == null ? Tri.TRUE : PredicateEvaluator.evaluate(r.when(), ctx);
            if (when == Tri.FALSE) {
                continue;
            }
            final Tri require = r.require() == null ? Tri.FALSE : PredicateEvaluator.evaluate(r.require(), ctx);
            if (require == Tri.TRUE) {
                continue;
            }
            final Severity severity = Severity.parse(r.severity(), Severity.ERROR);
            if (when == Tri.TRUE && require == Tri.FALSE) {
                out.add(new Finding(severity, "RULE_" + r.id(), Messages.render(r.message(), ctx),
                        r.property(), r.option(), Messages.render(r.suggestion(), ctx), sr.file()));
            } else if (severity != Severity.INFO) {
                final String what = r.description() != null ? r.description() : Messages.render(r.message(), ctx);
                out.add(new Finding(Severity.INFO, NOT_VERIFIED,
                        "Could not verify rule " + r.id() + " (" + what + "): it needs information that was not provided, such as the other workers or the target worker type",
                        r.property(), r.option(), null, sr.file()));
            }
        }
    }
}
