/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.oauth2;

/*-
 * #%L
 * jSentinel OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * No-mock mTLS: keytool-generated client + server keystores, a real {@link SSLServerSocket}
 * requiring client auth, and a real {@link SSLSocket} built from the {@link SSLContext}
 * that {@link MutualTls} produces. Proves the jSentinel-built context presents the client
 * certificate (handshake succeeds) and that a context without the client key is rejected.
 */
@DisplayName("mTLS — MutualTls SSLContext presents the client cert (RFC 8705)")
class MutualTlsTest {

  private static final char[] PW = "changeit".toCharArray();
  private static KeyStore clientKs;
  private static KeyStore clientTrust;
  private static KeyStore serverKs;
  private static KeyStore serverTrust;

  @BeforeAll
  static void generateKeystores(@TempDir Path dir) throws Exception {
    Path server = dir.resolve("server.p12");
    Path client = dir.resolve("client.p12");
    Path serverCrt = dir.resolve("server.crt");
    Path clientCrt = dir.resolve("client.crt");
    Path clientTrustP = dir.resolve("client-trust.p12");
    Path serverTrustP = dir.resolve("server-trust.p12");

    keytool("-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
        "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "1",
        "-keystore", server.toString(), "-storetype", "PKCS12", "-storepass", "changeit",
        "-keypass", "changeit", "-noprompt");
    keytool("-genkeypair", "-alias", "client", "-keyalg", "RSA", "-keysize", "2048",
        "-dname", "CN=test-client", "-validity", "1",
        "-keystore", client.toString(), "-storetype", "PKCS12", "-storepass", "changeit",
        "-keypass", "changeit", "-noprompt");
    keytool("-exportcert", "-alias", "server", "-keystore", server.toString(),
        "-storepass", "changeit", "-file", serverCrt.toString());
    keytool("-exportcert", "-alias", "client", "-keystore", client.toString(),
        "-storepass", "changeit", "-file", clientCrt.toString());
    keytool("-importcert", "-alias", "server", "-keystore", clientTrustP.toString(),
        "-storetype", "PKCS12", "-storepass", "changeit", "-file", serverCrt.toString(), "-noprompt");
    keytool("-importcert", "-alias", "client", "-keystore", serverTrustP.toString(),
        "-storetype", "PKCS12", "-storepass", "changeit", "-file", clientCrt.toString(), "-noprompt");

    clientKs = load(client);
    clientTrust = load(clientTrustP);
    serverKs = load(server);
    serverTrust = load(serverTrustP);
  }

  private static void keytool(String... args) throws Exception {
    Path javaHome = Path.of(System.getProperty("java.home"));
    String[] cmd = new String[args.length + 1];
    cmd[0] = javaHome.resolve("bin").resolve("keytool").toString();
    System.arraycopy(args, 0, cmd, 1, args.length);
    Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
    String out = new String(p.getInputStream().readAllBytes());
    int code = p.waitFor();
    if (code != 0) {
      throw new IllegalStateException("keytool failed (" + code + "): " + out);
    }
  }

  private static KeyStore load(Path p12) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(p12)) {
      ks.load(in, PW);
    }
    return ks;
  }

  private static SSLContext serverContext() throws Exception {
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(serverKs, PW);
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(serverTrust);
    SSLContext ctx = SSLContext.getInstance("TLSv1.3");
    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    return ctx;
  }

  @Test
  @DisplayName("the MutualTls client context completes a mutual-TLS handshake")
  void mutualHandshakeSucceeds() throws Exception {
    SSLContext clientCtx = MutualTls.sslContext(
        new MutualTlsClientConfig(clientKs, PW, "client"), clientTrust);

    ExecutorService pool = Executors.newSingleThreadExecutor();
    try (SSLServerSocket server =
        (SSLServerSocket) serverContext().getServerSocketFactory().createServerSocket(0, 1,
            java.net.InetAddress.getByName("127.0.0.1"))) {
      server.setNeedClientAuth(true);
      int port = server.getLocalPort();
      Future<String> serverSide = pool.submit(() -> {
        try (SSLSocket s = (SSLSocket) server.accept()) {
          s.getInputStream().read();
          s.getOutputStream().write(42);
          return ((java.security.cert.X509Certificate)
              s.getSession().getPeerCertificates()[0]).getSubjectX500Principal().getName();
        }
      });

      try (SSLSocket client = (SSLSocket) clientCtx.getSocketFactory()
          .createSocket("127.0.0.1", port)) {
        OutputStream os = client.getOutputStream();
        os.write(7);
        os.flush();
        InputStream is = client.getInputStream();
        assertEquals(42, is.read(), "server replied over the mutually-authenticated channel");
      }
      assertTrue(serverSide.get().contains("test-client"),
          "server saw the client certificate jSentinel presented");
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("a context without the client key cannot complete the client-auth handshake")
  void noClientCertRejected() throws Exception {
    // client trusts the server but presents NO certificate
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(clientTrust);
    SSLContext noKeyCtx = SSLContext.getInstance("TLSv1.3");
    noKeyCtx.init(null, tmf.getTrustManagers(), null);

    ExecutorService pool = Executors.newSingleThreadExecutor();
    try (SSLServerSocket server =
        (SSLServerSocket) serverContext().getServerSocketFactory().createServerSocket(0, 1,
            java.net.InetAddress.getByName("127.0.0.1"))) {
      server.setNeedClientAuth(true);
      int port = server.getLocalPort();
      pool.submit(() -> {
        try (SSLSocket s = (SSLSocket) server.accept()) {
          s.getInputStream().read();
        } catch (Exception ignored) {
          // handshake failure expected
        }
        return null;
      });
      assertThrows(Exception.class, () -> {
        try (SSLSocket client = (SSLSocket) noKeyCtx.getSocketFactory()
            .createSocket("127.0.0.1", port)) {
          client.startHandshake();
          client.getOutputStream().write(7);
          client.getInputStream().read();
        }
      });
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  @DisplayName("an empty keystore triggers the oauth2/mtls-keystore-empty STRICT failure")
  void emptyKeystoreRejected() throws Exception {
    KeyStore empty = KeyStore.getInstance("PKCS12");
    empty.load(null, PW);
    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> MutualTls.sslContext(new MutualTlsClientConfig(empty, PW, "client")));
    assertTrue(ex.getMessage().contains("oauth2/mtls-keystore-empty"));
  }

  @Test
  @DisplayName("endpointAlias remaps to the mtls_endpoint_aliases entry when present")
  void endpointAliasRemap() {
    URI plain = URI.create("https://op.example.com/token");
    URI mtls = URI.create("https://mtls.op.example.com/token");
    assertEquals(mtls, MutualTls.endpointAlias(Map.of("token_endpoint", mtls), "token_endpoint", plain));
    assertEquals(plain, MutualTls.endpointAlias(Map.of(), "token_endpoint", plain));
    assertEquals(plain, MutualTls.endpointAlias(null, "token_endpoint", plain));
  }

}
