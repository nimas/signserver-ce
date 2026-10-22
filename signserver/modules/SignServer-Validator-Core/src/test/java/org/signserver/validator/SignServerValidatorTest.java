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

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.validator.catalog.CatalogSource;
import org.signserver.validator.catalog.RuleCatalog;
import org.signserver.validator.cli.CommandLineTokenizer;
import org.signserver.validator.eval.ValueTypeRegistry;
import org.signserver.validator.report.Finding;
import org.signserver.validator.report.ReportFormatter;
import org.signserver.validator.report.Severity;
import org.signserver.validator.report.ValidationReport;

/**
 * Tests of the validator engine with the real catalog.
 *
 * @version $Id$
 */
public class SignServerValidatorTest {

    private static SignServerValidator validator;
    private static Path signserverHome;

    @BeforeClass
    public static void setUpClass() throws Exception {
        final Path rules = Path.of(System.getProperty("validator.rules.dir", "../../validator-rules"));
        signserverHome = Path.of(System.getProperty("signserver.home", "../.."));
        validator = new SignServerValidator(RuleCatalog.load(CatalogSource.directory(rules)));
    }

    private static Map<String, String> cms() {
        final Map<String, String> c = new LinkedHashMap<>();
        c.put("NAME", "CMSSigner");
        c.put("TYPE", "PROCESSABLE");
        c.put("IMPLEMENTATION_CLASS", "org.signserver.module.cmssigner.CMSSigner");
        c.put("CRYPTOTOKEN", "CryptoTokenP12");
        c.put("DEFAULTKEY", "signer00003");
        return c;
    }

    private static ValidationReport validate(final Map<String, String> config, final String cli) {
        return validator.validate(new ValidationRequest(config, cli, null, null, "test", false));
    }

    private static Finding find(final ValidationReport r, final String code, final String target) {
        return r.allFindings().stream().filter(f -> GoldenTestRunner.matches(f, code + ":" + target))
                .findFirst().orElse(null);
    }

    /** The example from the requirements: a PDFSigner property on a CMSSigner. */
    @Test
    public void testPdfPropertyOnCmsSigner() {
        final Map<String, String> c = cms();
        c.put("VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH", "/tmp/x.png");
        final ValidationReport r = validate(c, null);
        assertFalse(r.passed());
        final Finding f = find(r, "PROP_WRONG_WORKER", "VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH");
        assertNotNull(ReportFormatter.toText(r), f);
        assertEquals(Severity.ERROR, f.severity());
        assertEquals("VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH is not valid for CMSSigner (it is a property of PDFSigner)",
                f.message());
    }

    /** The example from the requirements: DIGESTALGORITHM=xyz. */
    @Test
    public void testInvalidDigestAlgorithm() {
        final Map<String, String> c = cms();
        c.put("IMPLEMENTATION_CLASS", "org.signserver.module.pdfsigner.PDFSigner");
        c.put("DIGESTALGORITHM", "xyz");
        final ValidationReport r = validate(c, null);
        assertFalse(r.passed());
        final Finding f = find(r, "VALUE_INVALID", "DIGESTALGORITHM");
        assertNotNull(ReportFormatter.toText(r), f);
        assertTrue(f.message(), f.message().startsWith("'xyz' is not a valid DIGESTALGORITHM for PDFSigner"));
    }

    @Test
    public void testValidConfigPasses() {
        final ValidationReport r = validate(cms(), null);
        assertTrue(ReportFormatter.toText(r), r.passed());
        assertEquals(0, r.summary().errors());
    }

    @Test
    public void testSensitiveValuesAreMasked() {
        final Map<String, String> c = cms();
        c.put("IMPLEMENTATION_CLASS", "org.signserver.module.pdfsigner.PDFSigner");
        c.put("TSA_URL", "not a url");
        c.put("TSA_PASSWORD", "topsecret");
        c.put("PIN", "1234");
        final String json = ReportFormatter.toJson(validate(c, null));
        assertFalse(json, json.contains("topsecret"));
        assertFalse(json, json.contains("1234"));
    }

    @Test
    public void testCombinationClientSide() {
        final Map<String, String> c = cms();
        c.put("ACCEPTED_HASH_DIGEST_ALGORITHMS", "SHA-256");
        final String cli = "signclient signdocument -workername CMSSigner -infile a -outfile b -clientside -digestalgorithm SHA256";
        ValidationReport r = validate(c, cli);
        assertNotNull(ReportFormatter.toText(r), find(r, "RULE_COMBO-CSH-2", "clientside"));
        c.put("CLIENTSIDEHASHING", "TRUE");
        r = validate(c, cli);
        assertTrue(ReportFormatter.toText(r), r.passed());
    }

    @Test
    public void testCliOnlyHasNoConfigSection() {
        final ValidationReport r = validate(null, "signclient signdocument -workername X -data hi");
        assertTrue(ReportFormatter.toText(r), r.passed());
        assertEquals(null, r.sections().config());
        assertEquals(null, r.sections().combination());
        assertNotNull(r.sections().cli());
    }

    @Test
    public void testSampleConfigsPass() throws Exception {
        final Path samples = signserverHome.resolve("doc/sample-configs");
        final List<String> files = List.of("cmssigner.properties", "plainsigner.properties",
                "pdfsigner.properties", "keystore-crypto.properties");
        for (String file : files) {
            try (InputStream in = Files.newInputStream(samples.resolve(file))) {
                final List<PropertiesConfigReader.Entry> entries = PropertiesConfigReader.read(in);
                assertEquals(file, 1, entries.size());
                final ValidationReport r = validate(entries.get(0).config(), null);
                assertTrue(file + "\n" + ReportFormatter.toText(r), r.passed());
                assertTrue(file + "\n" + ReportFormatter.toText(r), r.allFindings().stream()
                        .noneMatch(f -> f.code().startsWith("PROP_") || f.code().equals("VALUE_INVALID")));
            }
        }
    }

    @Test
    public void testTokenizer() {
        assertEquals(List.of("signdocument", "-metadata", "REASON=I agree", "-infile", "my file.pdf", "a\"b"),
                CommandLineTokenizer.tokenize("signdocument -metadata \"REASON=I agree\" -infile 'my file.pdf' a\\\"b"));
        assertEquals(List.of("a", "b"), CommandLineTokenizer.tokenize("a \\\n  b"));
    }

    @Test
    public void testAlgorithmChecks() {
        assertTrue(ValueTypeRegistry.isDigestAlgorithm("SHA256"));
        assertTrue(ValueTypeRegistry.isDigestAlgorithm("SHA-256"));
        assertFalse(ValueTypeRegistry.isDigestAlgorithm("xyz"));
        assertTrue(ValueTypeRegistry.isSignatureAlgorithm("SHA256withRSA"));
        assertTrue(ValueTypeRegistry.isSignatureAlgorithm("NONEwithRSA"));
        assertFalse(ValueTypeRegistry.isSignatureAlgorithm("SHA256withFOO"));
    }

    @Test
    public void testPropertiesReaderMultipleWorkers() throws Exception {
        final String text = "GLOB.X=1\nWORKER5.NAME=A\nWORKER5.TYPE=PROCESSABLE\nWORKERGENID1.NAME=B\n-WORKER6.FOO=1\n";
        final List<PropertiesConfigReader.Entry> e = PropertiesConfigReader.read(
                new java.io.ByteArrayInputStream(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(2, e.size());
        assertEquals("A", PropertiesConfigReader.select(e, "5").get().name());
        assertEquals("B", PropertiesConfigReader.select(e, "b").get().name());
        assertTrue(PropertiesConfigReader.select(e, null).isEmpty());
    }
}
