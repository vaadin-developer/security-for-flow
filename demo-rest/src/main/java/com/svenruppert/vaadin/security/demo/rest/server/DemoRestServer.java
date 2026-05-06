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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.bootstrap.BootstrapConfiguration;
import com.svenruppert.vaadin.security.bootstrap.BootstrapMode;
import com.svenruppert.vaadin.security.bootstrap.BootstrapStartup;
import com.svenruppert.vaadin.security.bootstrap.BootstrapStateService;
import com.svenruppert.vaadin.security.bootstrap.BootstrapTokenGenerator;
import com.svenruppert.vaadin.security.bootstrap.BootstrapTokenOutput;
import com.svenruppert.vaadin.security.bootstrap.BootstrapTokenStore;
import com.svenruppert.vaadin.security.bootstrap.ConsoleBootstrapTokenOutput;
import com.svenruppert.vaadin.security.bootstrap.FileBootstrapTokenOutput;
import com.svenruppert.vaadin.security.bootstrap.FileBootstrapTokenStore;
import com.svenruppert.vaadin.security.bootstrap.InMemoryBootstrapTokenStore;
import com.svenruppert.vaadin.security.bootstrap.InitialAdminBootstrapService;
import com.svenruppert.vaadin.security.bootstrap.MinimumLengthPasswordPolicy;
import com.svenruppert.vaadin.security.bootstrap.PasswordHasher;
import com.svenruppert.vaadin.security.bootstrap.Pbkdf2PasswordHasher;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoDocumentStore;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoRolePermissionMapping;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUserStore;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoEndpoints;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * Demo REST server using only JDK APIs ({@link HttpServer}).
 * <p>
 * Demo-only — token handling, password storage, and user persistence are
 * intentionally simple. Production systems must use a real authentication
 * subsystem.
 * <p>
 * Bootstrap mode is controlled by system properties — see
 * {@link DemoBootstrapEnvironment}.
 */
public final class DemoRestServer {

  private final HttpServer httpServer;
  private final int port;

  private DemoRestServer(HttpServer httpServer, int port) {
    this.httpServer = httpServer;
    this.port = port;
  }

  public static DemoRestServer start(int port) throws IOException {
    return start(port, DemoBootstrapEnvironment.fromEnvironment());
  }

  public static DemoRestServer start(int port, BootstrapConfiguration bootstrapConfig) throws IOException {
    boolean bootstrapMode = bootstrapConfig.mode() != BootstrapMode.DISABLED;
    PasswordHasher hasher = new Pbkdf2PasswordHasher();
    DemoUserStore users = new DemoUserStore(hasher, bootstrapMode);
    DemoTokenStore tokens = new DemoTokenStore();
    DemoDocumentStore documents = new DemoDocumentStore();
    DemoRolePermissionMapping mapping = new DemoRolePermissionMapping();
    DemoSubjectResolver resolver = new DemoSubjectResolver(tokens, mapping);
    DemoOperationRegistry registry = new DemoOperationRegistry();
    DemoHandlers handlers = new DemoHandlers(users, tokens, documents, registry, resolver);

    DemoAdministratorAccountStore adminStore = new DemoAdministratorAccountStore(users);
    BootstrapStateService stateService = new BootstrapStateService(adminStore, bootstrapConfig.mode());
    BootstrapTokenStore tokenStore = bootstrapTokenStore(bootstrapConfig);
    BootstrapTokenOutput tokenOutput = bootstrapTokenOutput(bootstrapConfig, port);
    InitialAdminBootstrapService bootstrapService = new InitialAdminBootstrapService(
        stateService, tokenStore, adminStore, hasher, new MinimumLengthPasswordPolicy(8),
        bootstrapConfig.tokenValidity(), java.time.Clock.systemUTC());
    DemoBootstrapHandlers bootstrapHandlers = new DemoBootstrapHandlers(stateService, bootstrapService);

    BootstrapStartup.initializeIfRequired(
        stateService, tokenStore, new BootstrapTokenGenerator(), tokenOutput, bootstrapConfig);

    DemoHttpRouter router = new DemoHttpRouter(handlers, bootstrapHandlers, resolver);
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext(DemoEndpoints.API_PREFIX, router);
    server.start();
    return new DemoRestServer(server, server.getAddress().getPort());
  }

  private static BootstrapTokenStore bootstrapTokenStore(BootstrapConfiguration cfg) {
    return cfg.mode() == BootstrapMode.PERSISTENT_FILE
        ? new FileBootstrapTokenStore(cfg.tokenFilePath())
        : new InMemoryBootstrapTokenStore();
  }

  private static BootstrapTokenOutput bootstrapTokenOutput(BootstrapConfiguration cfg, int port) {
    return switch (cfg.mode()) {
      case PERSISTENT_FILE -> new FileBootstrapTokenOutput();
      case TRANSIENT_CONSOLE -> new ConsoleBootstrapTokenOutput(
          "Open the Vaadin setup page or POST to /api/bootstrap/admin "
              + "(server on port " + port + ").");
      case DISABLED -> (token, configuration) -> {
        // no output
      };
    };
  }

  public int port() {
    return port;
  }

  public void stop() {
    httpServer.stop(0);
  }

  public static void main(String[] args) throws IOException {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
    DemoRestServer server = start(port);
    System.out.println("Demo REST server running on http://localhost:" + server.port());
    System.out.println("Default demo users: editor/editor, viewer/viewer "
        + "(admin/admin only when bootstrap is disabled).");
    System.out.println("Press Ctrl+C to stop.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }
}
