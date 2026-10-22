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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.signserver.validator.WorkerDirectory;

/**
 * Reads worker configurations from the SignServer REST API
 * (GET /signserver/rest/v1/workers and /workers/{id}). The API requires an
 * administrator client certificate and the X-Keyfactor-Requested-With header.
 * Also serves as a complete {@link WorkerDirectory} for cross-worker rules.
 *
 * @version $Id$
 */
public final class RestWorkerSource implements WorkerDirectory {

    /** Thrown when the server can not be used. */
    public static class RestException extends Exception {
        private static final long serialVersionUID = 1L;

        public RestException(final String message) {
            super(message);
        }

        public RestException(final String message, final Throwable cause) {
            super(message, cause);
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient client;
    private final String baseUrl;
    private Map<String, Integer> idsByName;
    private final Map<Integer, Map<String, String>> configs = new HashMap<>();

    /**
     * @param baseUrl e.g. https://localhost:8443/signserver/rest/v1
     * @param sslContext TLS settings with the admin client certificate
     */
    public RestWorkerSource(final String baseUrl, final SSLContext sslContext) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.client = HttpClient.newBuilder().sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(15)).build();
    }

    /**
     * Builds the TLS context from keystore files.
     *
     * @param keystore client (admin) keystore, PKCS12 or JKS
     * @param keystorePassword its password
     * @param truststore truststore with the server CA, or null for the JVM default
     * @param truststorePassword its password, or null
     */
    public static SSLContext sslContext(final Path keystore, final char[] keystorePassword,
            final Path truststore, final char[] truststorePassword) throws RestException {
        try {
            KeyManagerFactory kmf = null;
            if (keystore != null) {
                final KeyStore ks = loadKeyStore(keystore, keystorePassword);
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, keystorePassword);
            }
            TrustManagerFactory tmf = null;
            if (truststore != null) {
                final KeyStore ts = loadKeyStore(truststore, truststorePassword);
                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ts);
            }
            final SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf == null ? null : kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), null);
            return ctx;
        } catch (IOException | GeneralSecurityException ex) {
            throw new RestException("Unable to set up TLS: " + ex.getMessage(), ex);
        }
    }

    private static KeyStore loadKeyStore(final Path file, final char[] password)
            throws IOException, GeneralSecurityException {
        final String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        final KeyStore ks = KeyStore.getInstance(name.endsWith(".jks") ? "JKS" : "PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            ks.load(in, password);
        }
        return ks;
    }

    /**
     * @param idOrName worker ID or name
     * @return the worker ID
     * @throws RestException if there is no such worker or the call fails
     */
    public int resolveId(final String idOrName) throws RestException {
        final String s = idOrName.trim();
        if (s.matches("\\d+")) {
            return Integer.parseInt(s);
        }
        final Integer id = names().get(s.toUpperCase(Locale.ROOT));
        if (id == null) {
            throw new RestException("No worker named '" + s + "' on " + baseUrl);
        }
        return id;
    }

    /**
     * @param id worker ID
     * @return the worker configuration with upper-case keys
     */
    public Map<String, String> config(final int id) throws RestException {
        final Map<String, String> cached = configs.get(id);
        if (cached != null) {
            return cached;
        }
        final JsonNode props = get("/workers/" + id).path("properties");
        final Map<String, String> config = new LinkedHashMap<>();
        props.fields().forEachRemaining(e -> config.put(e.getKey().toUpperCase(Locale.ROOT), e.getValue().asText()));
        config.put(WORKERID_KEY, Integer.toString(id));
        configs.put(id, config);
        return config;
    }

    @Override
    public Optional<Map<String, String>> find(final String idOrName) {
        try {
            final String s = idOrName.trim();
            if (s.matches("\\d+") && !names().containsValue(Integer.valueOf(s))) {
                return Optional.empty();
            }
            if (!s.matches("\\d+") && !names().containsKey(s.toUpperCase(Locale.ROOT))) {
                return Optional.empty();
            }
            return Optional.of(config(resolveId(s)));
        } catch (RestException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    @Override
    public boolean isComplete() {
        return true;
    }

    private Map<String, Integer> names() throws RestException {
        if (idsByName == null) {
            final Map<String, Integer> m = new HashMap<>();
            for (JsonNode w : get("/workers").path("workers")) {
                m.put(w.path("name").asText().toUpperCase(Locale.ROOT), w.path("id").asInt());
            }
            idsByName = m;
        }
        return idsByName;
    }

    private JsonNode get(final String path) throws RestException {
        final HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Accept", "application/json")
                .header("X-Keyfactor-Requested-With", "signserver-validator")
                .timeout(Duration.ofSeconds(30))
                .GET().build();
        final HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException ex) {
            throw new RestException("Unable to connect to " + baseUrl + path + ": " + ex.getMessage(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RestException("Interrupted", ex);
        }
        final int status = response.statusCode();
        if (status == 403 || status == 401) {
            throw new RestException("Access denied (HTTP " + status + ") by " + baseUrl
                    + ": use an administrator client certificate (--keystore) authorized in SignServer");
        }
        if (status == 404) {
            throw new RestException("Not found (HTTP 404): " + baseUrl + path);
        }
        if (status != 200) {
            throw new RestException("HTTP " + status + " from " + baseUrl + path + ": " + response.body());
        }
        try {
            return JSON.readTree(response.body());
        } catch (IOException ex) {
            throw new RestException("Invalid JSON from " + baseUrl + path, ex);
        }
    }
}
