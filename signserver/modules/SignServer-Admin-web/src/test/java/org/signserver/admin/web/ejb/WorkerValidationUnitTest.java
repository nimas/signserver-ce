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
package org.signserver.admin.web.ejb;

import java.util.Arrays;
import java.util.Map;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.validator.report.ValidationReport;

/**
 * Tests running the validator through the local worker session.
 *
 * @version $Id$
 */
public class WorkerValidationUnitTest {

    private WorkerSessionLocal session;
    private WorkerConfig cms;

    private static WorkerConfig config(final Map<String, String> props) {
        final WorkerConfig wc = new WorkerConfig();
        props.forEach(wc::setProperty);
        return wc;
    }

    @Before
    public void setUp() throws Exception {
        session = mock(WorkerSessionLocal.class);
        cms = config(Map.of(
                "NAME", "CMSSigner",
                "TYPE", "PROCESSABLE",
                "IMPLEMENTATION_CLASS", "org.signserver.module.cmssigner.CMSSigner",
                "CRYPTOTOKEN", "CryptoTokenP12",
                "DEFAULTKEY", "signer00003"));
        final WorkerConfig token = config(Map.of(
                "NAME", "CryptoTokenP12",
                "TYPE", "CRYPTO_WORKER",
                "IMPLEMENTATION_CLASS", "org.signserver.server.signers.CryptoWorker",
                "CRYPTOTOKEN_IMPLEMENTATION_CLASS", "org.signserver.server.cryptotokens.KeystoreCryptoToken",
                "KEYSTORETYPE", "PKCS12",
                "KEYSTOREPATH", "/tmp/ks.p12"));
        when(session.getCurrentWorkerConfig(any(), eq(5))).thenAnswer(i -> cms);
        when(session.getCurrentWorkerConfig(any(), eq(1))).thenReturn(token);
        when(session.getWorkerId("CryptoTokenP12")).thenReturn(1);
        when(session.getWorkerId("NoSuchToken")).thenReturn(0);
        when(session.getAllWorkers()).thenReturn(Arrays.asList(1, 5));
    }

    @Test
    public void testValidWorkerPassesAndCryptoTokenIsVerified() throws Exception {
        final ValidationReport r = WorkerValidation.validate(session, null, 5, null);
        assertTrue(r.allFindings().toString(), r.passed());
        assertTrue(r.allFindings().toString(), r.allFindings().stream().noneMatch(f -> f.code().equals("NOT_VERIFIED")));
    }

    @Test
    public void testWrongPropertyAndMissingToken() throws Exception {
        cms.setProperty("VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH", "/tmp/x.png");
        cms.setProperty("CRYPTOTOKEN", "NoSuchToken");
        final ValidationReport r = WorkerValidation.validate(session, null, 5, null);
        assertFalse(r.passed());
        assertTrue(r.allFindings().toString(), r.allFindings().stream().anyMatch(f -> f.code().equals("PROP_WRONG_WORKER")));
        assertTrue(r.allFindings().toString(), r.allFindings().stream().anyMatch(f -> f.code().equals("RULE_BP-TOKEN-2")));
    }

    @Test
    public void testWithCommand() throws Exception {
        final ValidationReport r = WorkerValidation.validate(session, null, 5,
                "signclient signdocument -workername CMSSigner -infile a -outfile b -clientside -digestalgorithm SHA-256");
        assertFalse(r.passed());
        assertTrue(r.allFindings().toString(), r.allFindings().stream().anyMatch(f -> f.code().equals("RULE_COMBO-CSH-2")));
    }
}
