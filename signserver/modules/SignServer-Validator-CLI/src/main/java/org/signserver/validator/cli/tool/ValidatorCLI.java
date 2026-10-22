package org.signserver.validator.cli.tool;

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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.signserver.validator.GoldenTestRunner;
import org.signserver.validator.PropertiesConfigReader;
import org.signserver.validator.SignServerValidator;
import org.signserver.validator.ValidationRequest;
import org.signserver.validator.WorkerDirectory;
import org.signserver.validator.catalog.CatalogException;
import org.signserver.validator.catalog.CatalogSource;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.extract.DriftChecker;
import org.signserver.validator.report.ReportFormatter;
import org.signserver.validator.report.ValidationReport;

/**
 * Command line front end: bin/signserver-validator.
 *
 * <pre>
 * signserver-validator validate --worker CMSSigner [--cli "signclient signdocument ..."]
 *     [--url https://localhost:8443] --keystore admin.p12 [--truststore truststore.jks]
 * signserver-validator validate --config-file cmssigner.properties [--worker NAME] [--cli "..."]
 * signserver-validator validate --cli "signclient signdocument ..."
 * signserver-validator selftest              run the golden tests of the rule catalog
 * signserver-validator drift                 compare the rule catalog with the sources
 * </pre>
 *
 * Exit code: 0 validation passed, 1 validation failed, 2 usage or connection error.
 *
 * @version $Id$
 */
public final class ValidatorCLI {

    public static final int EXIT_PASSED = 0;
    public static final int EXIT_FAILED = 1;
    public static final int EXIT_ERROR = 2;

    /** System property with a catalog directory overriding the embedded one. */
    public static final String RULES_PROPERTY = "signserver.validator.rules";

    private static final String DEFAULT_URL = "https://localhost:8443";
    private static final String KEYSTORE_PASSWORD_ENV = "SIGNSERVER_VALIDATOR_KEYSTORE_PASSWORD";
    private static final String TRUSTSTORE_PASSWORD_ENV = "SIGNSERVER_VALIDATOR_TRUSTSTORE_PASSWORD";

    private final PrintStream out;
    private final PrintStream err;

    public ValidatorCLI(final PrintStream out, final PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public static void main(final String[] args) {
        System.exit(new ValidatorCLI(System.out, System.err).run(args));
    }

    static Options options() {
        final Options o = new Options();
        o.addOption(Option.builder().longOpt("worker").hasArg().argName("id|name")
                .desc("Worker to validate: ID or name on the server, or NAME/ID/WORKERGENIDn in --config-file").build());
        o.addOption(Option.builder().longOpt("config-file").hasArg().argName("file")
                .desc("Read the worker configuration from a properties file instead of the server").build());
        o.addOption(Option.builder().longOpt("cli").hasArg().argName("command")
                .desc("signclient command line to validate, e.g. \"signclient signdocument -workername X -data hi\"").build());
        o.addOption(Option.builder().longOpt("url").hasArg().argName("url")
                .desc("SignServer base URL (default " + DEFAULT_URL + "); /signserver/rest/v1 is added if no path is given").build());
        o.addOption(Option.builder().longOpt("keystore").hasArg().argName("file")
                .desc("Administrator client keystore (PKCS12 or JKS) for the REST API").build());
        o.addOption(Option.builder().longOpt("keystorepwd").hasArg().argName("password")
                .desc("Keystore password (or set " + KEYSTORE_PASSWORD_ENV + ", or be prompted)").build());
        o.addOption(Option.builder().longOpt("truststore").hasArg().argName("file")
                .desc("Truststore with the SignServer TLS CA (default: Java truststore)").build());
        o.addOption(Option.builder().longOpt("truststorepwd").hasArg().argName("password")
                .desc("Truststore password (or set " + TRUSTSTORE_PASSWORD_ENV + ")").build());
        o.addOption(Option.builder().longOpt("rules").hasArg().argName("dir")
                .desc("Rule catalog directory (default: $SIGNSERVER_HOME/validator-rules if present, else the embedded catalog)").build());
        o.addOption(Option.builder().longOpt("format").hasArg().argName("json|text")
                .desc("Output format (default json)").build());
        o.addOption(Option.builder().longOpt("strict").desc("Warnings also make the validation fail").build());
        o.addOption(Option.builder().longOpt("signserver-home").hasArg().argName("dir")
                .desc("SignServer directory with the sources (drift only, default: current directory)").build());
        o.addOption(Option.builder().longOpt("help").desc("Show this help").build());
        o.addOption(Option.builder().longOpt("version").desc("Show the version").build());
        return o;
    }

    public int run(final String[] args) {
        final CommandLine line;
        try {
            line = new DefaultParser().parse(options(), args);
        } catch (ParseException ex) {
            err.println("Error: " + ex.getMessage());
            usage();
            return EXIT_ERROR;
        }
        final List<String> rest = line.getArgList();
        if (line.hasOption("help") || rest.isEmpty() && !line.hasOption("version")) {
            usage();
            return line.hasOption("help") ? EXIT_PASSED : EXIT_ERROR;
        }
        try {
            final RuleCatalog catalog = loadCatalog(line);
            if (line.hasOption("version")) {
                out.println("signserver-validator " + SignServerValidator.VERSION + ", rule catalog "
                        + catalog.getCatalogVersion() + " (" + catalog.getSourceDescription() + ")");
                return EXIT_PASSED;
            }
            switch (rest.get(0)) {
                case "validate":
                    return validate(line, catalog);
                case "selftest":
                    return selftest(catalog);
                case "drift":
                    return drift(line, catalog);
                default:
                    err.println("Error: unknown command '" + rest.get(0) + "'");
                    usage();
                    return EXIT_ERROR;
            }
        } catch (CatalogException ex) {
            err.println(ex.getMessage());
            return EXIT_ERROR;
        } catch (UsageException | RestWorkerSource.RestException | IOException | IllegalStateException ex) {
            err.println("Error: " + ex.getMessage());
            return EXIT_ERROR;
        }
    }

    private static RuleCatalog loadCatalog(final CommandLine line) throws CatalogException {
        String dir = line.getOptionValue("rules");
        if (dir == null) {
            dir = System.getProperty(RULES_PROPERTY);
        }
        return RuleCatalog.load(dir == null || dir.isBlank() ? CatalogSource.embedded()
                : CatalogSource.directory(Path.of(dir)));
    }

    private int validate(final CommandLine line, final RuleCatalog catalog)
            throws UsageException, RestWorkerSource.RestException, IOException {
        final String worker = line.getOptionValue("worker");
        final String configFile = line.getOptionValue("config-file");
        final String cli = line.getOptionValue("cli");
        if (worker == null && configFile == null && cli == null) {
            throw new UsageException("Give --worker and/or --config-file, and/or --cli");
        }

        Map<String, String> config = null;
        WorkerDirectory directory = null;
        Integer workerId = null;
        String source = null;
        if (configFile != null) {
            final List<PropertiesConfigReader.Entry> entries;
            try (InputStream in = Files.newInputStream(Path.of(configFile))) {
                entries = PropertiesConfigReader.read(in);
            }
            final Optional<PropertiesConfigReader.Entry> selected = PropertiesConfigReader.select(entries, worker);
            if (selected.isEmpty()) {
                throw new UsageException((worker == null ? "The file has several workers; select one with --worker: "
                        : "No worker '" + worker + "' in the file; available: ")
                        + entries.stream().map(e -> e.key() + (e.name() != null ? " (" + e.name() + ")" : ""))
                        .collect(Collectors.joining(", ")));
            }
            config = selected.get().config();
            workerId = selected.get().workerId();
            directory = WorkerDirectory.of(entries.stream().map(PropertiesConfigReader.Entry::config).toList(), false);
            source = "file " + configFile;
        } else if (worker != null) {
            final String url = restUrl(line.getOptionValue("url", DEFAULT_URL));
            final RestWorkerSource rest = new RestWorkerSource(url, sslContext(line));
            workerId = rest.resolveId(worker);
            config = rest.config(workerId);
            directory = rest;
            source = "REST " + url;
        }

        final ValidationReport report = new SignServerValidator(catalog).validate(
                new ValidationRequest(config, cli, directory, workerId, source, line.hasOption("strict")));
        final String format = line.getOptionValue("format", "json");
        out.println("text".equalsIgnoreCase(format) ? ReportFormatter.toText(report) : ReportFormatter.toJson(report));
        return report.passed() ? EXIT_PASSED : EXIT_FAILED;
    }

    private int selftest(final RuleCatalog catalog) {
        final List<GoldenTestRunner.Outcome> outcomes = new GoldenTestRunner(catalog).runAll();
        int failed = 0;
        for (GoldenTestRunner.Outcome o : outcomes) {
            if (o.passed()) {
                out.println("PASS " + o.file() + " / " + o.name());
            } else {
                failed++;
                out.println("FAIL " + o.file() + " / " + o.name());
                o.problems().forEach(p -> out.println("     " + p));
            }
        }
        out.println(outcomes.size() - failed + "/" + outcomes.size() + " golden tests passed (rule catalog "
                + catalog.getCatalogVersion() + ", " + catalog.getSourceDescription() + ")");
        return failed == 0 ? EXIT_PASSED : EXIT_FAILED;
    }

    private int drift(final CommandLine line, final RuleCatalog catalog) throws IOException {
        final Path home = Path.of(line.getOptionValue("signserver-home", "."));
        final List<DriftChecker.Entry> entries = new DriftChecker(catalog, home).check();
        if ("text".equalsIgnoreCase(line.getOptionValue("format", "json"))) {
            for (DriftChecker.Entry e : entries) {
                out.println((e.hasDrift() ? "DRIFT " : "OK    ") + e.catalogFile());
                if (!e.missingInCatalog().isEmpty()) {
                    out.println("      in code, missing in catalog: " + e.missingInCatalog());
                }
                if (!e.notFoundInCode().isEmpty()) {
                    out.println("      in catalog, not found in code: " + e.notFoundInCode());
                }
                e.errors().forEach(x -> out.println("      " + x));
            }
        } else {
            out.println(new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(entries));
        }
        return entries.stream().anyMatch(DriftChecker.Entry::hasDrift) ? EXIT_FAILED : EXIT_PASSED;
    }

    /** Adds /signserver/rest/v1 to a URL without path. */
    static String restUrl(final String url) throws UsageException {
        final URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException ex) {
            throw new UsageException("Invalid --url: " + url);
        }
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new UsageException("Invalid --url, expected e.g. https://localhost:8443: " + url);
        }
        final String path = uri.getPath() == null ? "" : uri.getPath();
        final String base = url.trim().replaceAll("/+$", "");
        return path.isEmpty() || path.equals("/") ? base + "/signserver/rest/v1" : base;
    }

    private SSLContext sslContext(final CommandLine line) throws RestWorkerSource.RestException, UsageException {
        final String keystore = line.getOptionValue("keystore");
        if (keystore == null) {
            throw new UsageException("--keystore with an administrator certificate is needed to read the worker configuration over REST"
                    + " (or use --config-file)");
        }
        final char[] ksPwd = password(line.getOptionValue("keystorepwd"), KEYSTORE_PASSWORD_ENV,
                "Password for keystore " + keystore + ": ");
        final String truststore = line.getOptionValue("truststore");
        final char[] tsPwd = truststore == null ? null
                : password(line.getOptionValue("truststorepwd"), TRUSTSTORE_PASSWORD_ENV, null);
        return RestWorkerSource.sslContext(Path.of(keystore), ksPwd,
                truststore == null ? null : Path.of(truststore), tsPwd);
    }

    private static char[] password(final String given, final String env, final String prompt) {
        if (given != null) {
            return given.toCharArray();
        }
        final String fromEnv = System.getenv(env);
        if (fromEnv != null) {
            return fromEnv.toCharArray();
        }
        final Console console = System.console();
        if (prompt != null && console != null) {
            return console.readPassword("%s", prompt);
        }
        return prompt == null ? null : new char[0];
    }

    private void usage() {
        final HelpFormatter f = new HelpFormatter();
        final java.io.PrintWriter pw = new java.io.PrintWriter(new java.io.OutputStreamWriter(err, StandardCharsets.UTF_8), true);
        f.printHelp(pw, 110, "signserver-validator <validate|selftest|drift> [options]",
                "\nValidates SignServer worker configurations and signclient commands against the rule catalog.\n\n",
                options(), 2, 2,
                "\nExamples:\n"
                + "  signserver-validator validate --worker CMSSigner --keystore admin.p12 --truststore truststore.jks\n"
                + "  signserver-validator validate --config-file doc/sample-configs/cmssigner.properties \\\n"
                + "      --cli \"signclient signdocument -workername CMSSigner -infile a.txt -outfile a.p7s\"\n"
                + "  signserver-validator validate --cli \"signclient signdocument -workername X -data hi\" --format text\n"
                + "\nExit code: 0 passed, 1 failed, 2 error.", false);
        pw.flush();
    }

    /** Wrong use of the command line. */
    static class UsageException extends Exception {
        private static final long serialVersionUID = 1L;

        UsageException(final String message) {
            super(message);
        }
    }
}
