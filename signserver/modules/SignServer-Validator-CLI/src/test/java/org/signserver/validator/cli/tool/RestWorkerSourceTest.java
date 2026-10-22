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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.net.ssl.SSLContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.signserver.validator.SignServerValidator;
import org.signserver.validator.ValidationRequest;
import org.signserver.validator.report.ValidationReport;

/**
 * Tests the REST client against a local stand-in for the SignServer REST API.
 *
 * @version $Id$
 */
public class RestWorkerSourceTest {

    private HttpServer server;
    private String baseUrl;
    private volatile boolean deny;

    @Before
    public void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/signserver/rest/v1/workers", this::handle);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/signserver/rest/v1";
    }

    @After
    public void tearDown() {
        server.stop(0);
    }

    private void handle(final HttpExchange ex) throws IOException {
        final String path = ex.getRequestURI().getPath();
        String body;
        int status = 200;
        if (deny || ex.getRequestHeaders().getFirst("X-Keyfactor-Requested-With") == null) {
            status = 403;
            body = "{\"error\":\"Forbidden\"}";
        } else if (path.endsWith("/workers")) {
            body = "{\"workers\":[{\"id\":1,\"name\":\"CryptoTokenP12\"},{\"id\":5,\"name\":\"CMSSigner\"}]}";
        } else if (path.endsWith("/workers/5")) {
            body = "{\"properties\":{\"NAME\":\"CMSSigner\",\"TYPE\":\"PROCESSABLE\","
                    + "\"IMPLEMENTATION_CLASS\":\"org.signserver.module.cmssigner.CMSSigner\","
                    + "\"CRYPTOTOKEN\":\"CryptoTokenP12\",\"DEFAULTKEY\":\"signer00003\"}}";
        } else if (path.endsWith("/workers/1")) {
            body = "{\"properties\":{\"NAME\":\"CryptoTokenP12\",\"TYPE\":\"CRYPTO_WORKER\","
                    + "\"IMPLEMENTATION_CLASS\":\"org.signserver.server.signers.CryptoWorker\","
                    + "\"CRYPTOTOKEN_IMPLEMENTATION_CLASS\":\"org.signserver.server.cryptotokens.KeystoreCryptoToken\","
                    + "\"KEYSTORETYPE\":\"PKCS12\",\"KEYSTOREPATH\":\"/tmp/ks.p12\",\"KEYSTOREPASSWORD\":\"_MASKED_\"}}";
        } else {
            status = 404;
            body = "{}";
        }
        final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Test
    public void testResolveAndValidateWithDirectory() throws Exception {
        final RestWorkerSource rest = new RestWorkerSource(baseUrl, SSLContext.getDefault());
        assertEquals(5, rest.resolveId("cmssigner"));
        assertEquals(5, rest.resolveId("5"));
        final Map<String, String> config = rest.config(5);
        assertEquals("CMSSigner", config.get("NAME"));

        final ValidationReport r = SignServerValidator.withEmbeddedCatalog().validate(
                new ValidationRequest(config, null, rest, 5, "REST", false));
        assertTrue(r.allFindings().toString(), r.passed());
        // CRYPTOTOKEN is verified against the server's worker list: no NOT_VERIFIED
        assertTrue(r.allFindings().toString(), r.allFindings().stream().noneMatch(f -> f.code().equals("NOT_VERIFIED")));
        assertEquals(Integer.valueOf(5), r.target().workerId());
    }

    @Test
    public void testMissingCryptoWorkerIsAnErrorOnline() throws Exception {
        final RestWorkerSource rest = new RestWorkerSource(baseUrl, SSLContext.getDefault());
        final Map<String, String> config = new java.util.LinkedHashMap<>(rest.config(5));
        config.put("CRYPTOTOKEN", "NoSuchToken");
        final ValidationReport r = SignServerValidator.withEmbeddedCatalog().validate(
                new ValidationRequest(config, null, rest, 5, "REST", false));
        assertTrue(r.allFindings().toString(), r.allFindings().stream()
                .anyMatch(f -> f.code().equals("RULE_BP-TOKEN-2")));
    }

    @Test
    public void testUnknownWorkerAndAccessDenied() throws Exception {
        final RestWorkerSource rest = new RestWorkerSource(baseUrl, SSLContext.getDefault());
        try {
            rest.resolveId("Nope");
            fail("unknown worker accepted");
        } catch (RestWorkerSource.RestException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("No worker named 'Nope'"));
        }
        deny = true;
        try {
            new RestWorkerSource(baseUrl, SSLContext.getDefault()).resolveId("CMSSigner");
            fail("403 not reported");
        } catch (RestWorkerSource.RestException ex) {
            assertTrue(ex.getMessage(), ex.getMessage().contains("administrator client certificate"));
        }
    }
}
