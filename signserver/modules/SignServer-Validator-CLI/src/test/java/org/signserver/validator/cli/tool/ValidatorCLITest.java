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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * Tests of the command line front end (no server needed).
 *
 * @version $Id$
 */
public class ValidatorCLITest {

    private static final String SAMPLES = "../../doc/sample-configs/";

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(final String... args) {
        out.reset();
        err.reset();
        return new ValidatorCLI(new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8)).run(args);
    }

    private String out() {
        return out.toString(StandardCharsets.UTF_8);
    }

    @Test
    public void testSampleConfigFilePasses() {
        assertEquals(err.toString(), ValidatorCLI.EXIT_PASSED,
                run("validate", "--config-file", SAMPLES + "cmssigner.properties"));
        assertTrue(out(), out().contains("\"passed\" : true"));
    }

    @Test
    public void testWrongPropertyFails() throws Exception {
        final Path file = Files.createTempFile("cms", ".properties");
        Files.writeString(file, Files.readString(Path.of(SAMPLES + "cmssigner.properties"))
                + "\nWORKERGENID1.VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH=/tmp/x.png\n");
        assertEquals(ValidatorCLI.EXIT_FAILED, run("validate", "--config-file", file.toString(), "--format", "text"));
        assertTrue(out(), out().contains("PROP_WRONG_WORKER VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH"));
        assertTrue(out(), out().contains("RESULT: FAILED"));
    }

    @Test
    public void testConfigAndCli() {
        assertEquals(ValidatorCLI.EXIT_FAILED, run("validate", "--config-file", SAMPLES + "cmssigner.properties",
                "--cli", "signclient signdocument -workername CMSSigner -infile a -outfile b -clientside -digestalgorithm SHA-256"));
        assertTrue(out(), out().contains("RULE_COMBO-CSH-2"));
    }

    @Test
    public void testCliOnly() {
        assertEquals(ValidatorCLI.EXIT_FAILED, run("validate", "--cli", "signclient signdocument -workerName X -data hi"));
        assertTrue(out(), out().contains("CLI_UNKNOWN_OPTION"));
    }

    @Test
    public void testUsageErrors() {
        assertEquals(ValidatorCLI.EXIT_ERROR, run());
        assertEquals(ValidatorCLI.EXIT_ERROR, run("validate"));
        assertEquals(ValidatorCLI.EXIT_ERROR, run("validate", "--worker", "CMSSigner"));
        assertTrue(err.toString(), err.toString().contains("--keystore"));
    }

    @Test
    public void testMissingKeystoreFile() {
        assertEquals(ValidatorCLI.EXIT_ERROR, run("validate", "--worker", "CMSSigner",
                "--keystore", "does-not-exist.p12", "--keystorepwd", "x"));
        assertTrue(err.toString(), err.toString().contains("Keystore file not found"));
    }

    @Test
    public void testSelftest() {
        assertEquals(out(), ValidatorCLI.EXIT_PASSED, run("selftest"));
        assertTrue(out(), out().contains("golden tests passed"));
    }

    @Test
    public void testRestUrl() throws Exception {
        assertEquals("https://localhost:8443/signserver/rest/v1", ValidatorCLI.restUrl("https://localhost:8443"));
        assertEquals("https://h:8443/signserver/rest/v1", ValidatorCLI.restUrl("https://h:8443/"));
        assertEquals("https://h/custom/rest/v1", ValidatorCLI.restUrl("https://h/custom/rest/v1"));
    }
}
