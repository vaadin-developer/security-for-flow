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

import com.svenruppert.vaadin.security.accountlifecycle.InMemoryPasswordResetTokenStore;
import com.svenruppert.vaadin.security.accountlifecycle.LoggingNotificationSender;
import com.svenruppert.vaadin.security.accountlifecycle.PasswordResetService;
import com.svenruppert.vaadin.security.authentication.ApiKeyAuthenticationService;
import com.svenruppert.vaadin.security.authentication.ApiKeyStore;
import com.svenruppert.vaadin.security.authentication.InMemoryApiKeyStore;
import com.svenruppert.vaadin.security.authentication.InMemoryRefreshTokenStore;
import com.svenruppert.vaadin.security.authentication.TokenService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.ratelimiting.InMemoryRateLimitPolicy;
import com.svenruppert.vaadin.security.ratelimiting.InMemoryRateLimitStore;
import com.svenruppert.vaadin.security.ratelimiting.RateLimitPolicy;

import java.time.Duration;
import com.svenruppert.vaadin.security.logout.SubjectClearingLogoutService;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
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
import com.svenruppert.vaadin.security.bruteforce.InMemoryLoginAttemptPolicy;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoDocumentStore;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoOwnedDocumentStore;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoRolePermissionMapping;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUser;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUserStore;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoEndpoints;
import com.svenruppert.vaadin.security.policy.impl.InMemoryPolicyRegistry;
import com.svenruppert.vaadin.security.policy.impl.InMemoryResourceResolverRegistry;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;
import com.svenruppert.vaadin.security.policy.spi.ResourceResolverRegistry;
import com.svenruppert.vaadin.security.rest.RestSecurityVersionFilter;
import com.svenruppert.vaadin.security.session.InMemorySecurityVersionStore;
import com.svenruppert.vaadin.security.session.SecurityVersionEnforcer;
import com.svenruppert.vaadin.security.session.SecurityVersionStore;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Optional;

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
  private final com.svenruppert.vaadin.security.rest.RestSubjectResolver subjectResolver;

  private DemoRestServer(HttpServer httpServer, int port) {
    this(httpServer, port, null);
  }

  private DemoRestServer(HttpServer httpServer, int port,
                         com.svenruppert.vaadin.security.rest.RestSubjectResolver subjectResolver) {
    this.httpServer = httpServer;
    this.port = port;
    this.subjectResolver = subjectResolver;
  }

  public static DemoRestServer start(int port) throws IOException {
    return start(port, DemoBootstrapEnvironment.fromEnvironment(),
        new InMemoryLoginAttemptPolicy(),
        new InMemoryLoginAttemptPolicy(
            com.svenruppert.vaadin.security.bruteforce.LoginAttemptConfiguration.strictBootstrap(),
            java.time.Clock.systemUTC(),
            null));
  }

  public static DemoRestServer start(int port, BootstrapConfiguration bootstrapConfig) throws IOException {
    return start(port, bootstrapConfig,
        new InMemoryLoginAttemptPolicy(),
        new InMemoryLoginAttemptPolicy(
            com.svenruppert.vaadin.security.bruteforce.LoginAttemptConfiguration.strictBootstrap(),
            java.time.Clock.systemUTC(),
            null));
  }

  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     LoginAttemptPolicy loginAttemptPolicy) throws IOException {
    return start(port, bootstrapConfig, loginAttemptPolicy,
        new InMemoryLoginAttemptPolicy(
            com.svenruppert.vaadin.security.bruteforce.LoginAttemptConfiguration.strictBootstrap(),
            java.time.Clock.systemUTC(),
            null));
  }

  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     LoginAttemptPolicy loginAttemptPolicy,
                                     LoginAttemptPolicy bootstrapAttemptPolicy) throws IOException {
    boolean bootstrapMode = bootstrapConfig.mode() != BootstrapMode.DISABLED;
    com.svenruppert.vaadin.security.credential.password.PasswordHashingService hashingService =
        com.svenruppert.vaadin.security.credential.password.PasswordHashingServices.defaults();
    DemoUserStore users = new DemoUserStore(hashingService, bootstrapMode);
    DemoTokenStore tokens = new DemoTokenStore();
    DemoDocumentStore documents = new DemoDocumentStore();
    DemoRolePermissionMapping mapping = new DemoRolePermissionMapping();
    // V00.70 Phase-7b API keys — the resolver checks X-Api-Key
    // ahead of the Bearer token (scopes win over session perms).
    ApiKeyStore apiKeyStore = new InMemoryApiKeyStore();
    Sha256TokenHasher apiKeyHasher = new Sha256TokenHasher();
    ApiKeyAuthenticationService apiKeyAuth = new ApiKeyAuthenticationService(
        apiKeyStore, apiKeyHasher,
        SecurityServiceResolver.securityAuditService());
    DemoSubjectResolver resolver = new DemoSubjectResolver(
        tokens, mapping, apiKeyAuth);
    DemoOperationRegistry registry = new DemoOperationRegistry();
    SecurityVersionStore versionStore = new InMemorySecurityVersionStore();
    // PasswordResetService requires a *deterministic* hasher so the
    // token-hash → record lookup actually matches. The SPI-resolved
    // PasswordHasher (PBKDF2 / Argon2id) is salted by design and would
    // produce a different hash every call — wrong tool for this job.
    PasswordResetService passwordResetService = new PasswordResetService(
        new InMemoryPasswordResetTokenStore(),
        new Sha256TokenHasher(),
        SecurityServiceResolver.securityAuditService(),
        new LoggingNotificationSender());
    // V00.70 Phase-7c per-IP login rate limiting — 200 attempts per minute.
    // Sits ahead of the per-username brute-force window so distributed
    // credential stuffing surfaces as 429 + Retry-After before the
    // per-username lockout even sees the request. The threshold is
    // deliberately high enough that the integration-test fixture (which
    // logs in as multiple demo users from the same loopback IP within a
    // minute) does not trip the limit; tests that need to exercise the
    // 429 path construct a dedicated InMemoryRateLimitPolicy with a
    // smaller limit (see DemoLoginRateLimitTest).
    RateLimitPolicy loginRateLimit = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(),
        SecurityServiceResolver.securityAuditService(),
        200,
        Duration.ofMinutes(1));
    // V00.70 Phase-7b — rotating refresh tokens. Uses the same
    // Sha256TokenHasher as API keys (deterministic lookup) and a
    // dedicated InMemoryRefreshTokenStore.
    TokenService tokenService = new TokenService(
        new InMemoryRefreshTokenStore(),
        apiKeyHasher,
        SecurityServiceResolver.securityAuditService());
    DemoHandlers handlers = new DemoHandlers(
        users, tokens, documents, registry, resolver, loginAttemptPolicy,
        versionStore, passwordResetService, loginRateLimit,
        apiKeyStore, apiKeyHasher, tokenService);

    // V00.70 Policy-DSL example — register the document.owner-or-admin
    // policy and the matching ResourceResolver, then inject the
    // owned-documents store into the handlers so the inspect handler
    // can serve the JSON body after the policy has cleared.
    DemoOwnedDocumentStore ownedDocumentStore = new DemoOwnedDocumentStore();
    handlers.setOwnedDocumentStore(ownedDocumentStore);
    PolicyRegistry policyRegistry = new InMemoryPolicyRegistry();
    policyRegistry.register(DemoPolicies.documentOwnerOrAdmin());
    SecurityServiceResolver.setPolicyRegistry(policyRegistry);
    ResourceResolverRegistry resourceRegistry = new InMemoryResourceResolverRegistry();
    resourceRegistry.register(new DemoOwnedDocumentResolver(ownedDocumentStore));
    SecurityServiceResolver.setResourceResolverRegistry(resourceRegistry);
    SecurityVersionEnforcer versionEnforcer = new SecurityVersionEnforcer(
        versionStore, SecurityServiceResolver.securityAuditService());
    RestSecurityVersionFilter versionFilter = new RestSecurityVersionFilter(
        resolver, versionEnforcer);

    SubjectClearingLogoutService<DemoUser> logoutService = new SubjectClearingLogoutService<>(
        NoopSubjectStore.INSTANCE, DemoUser.class, tokens, null);
    logoutService.addListener((subjectId, sessionId, scope) -> {
      if (sessionId != null) {
        tokens.revoke(sessionId);
      }
    });
    SecurityServiceResolver.setLogoutService(logoutService);

    DemoAdministratorAccountStore adminStore = new DemoAdministratorAccountStore(users);
    BootstrapStateService stateService = new BootstrapStateService(adminStore, bootstrapConfig.mode());
    BootstrapTokenStore tokenStore = bootstrapTokenStore(bootstrapConfig);
    BootstrapTokenOutput tokenOutput = bootstrapTokenOutput(bootstrapConfig, port);
    InitialAdminBootstrapService bootstrapService = new InitialAdminBootstrapService(
        stateService, tokenStore, adminStore, hashingService, new MinimumLengthPasswordPolicy(8),
        bootstrapConfig.tokenValidity(), java.time.Clock.systemUTC());
    DemoBootstrapHandlers bootstrapHandlers = new DemoBootstrapHandlers(
        stateService, bootstrapService, bootstrapAttemptPolicy);

    BootstrapStartup.initializeIfRequired(
        stateService, tokenStore, new BootstrapTokenGenerator(), tokenOutput, bootstrapConfig);

    DemoHttpRouter router = new DemoHttpRouter(
        handlers, bootstrapHandlers, resolver, versionFilter);
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext(DemoEndpoints.API_PREFIX, router);
    server.start();
    return new DemoRestServer(server, server.getAddress().getPort(), resolver);
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

  /**
   * No-op {@link SubjectStore} for the REST demo. REST handlers don't bind
   * the current subject to a thread-local; the token store is authoritative.
   */
  private enum NoopSubjectStore implements SubjectStore {
    INSTANCE;

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.empty();
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
    }
  }

  public static void main(String[] args) throws IOException {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
    DemoRestServer server = start(port);
    // V00.72 fluent bootstrap. DemoRestServer wires its own AuthN +
    // RestSubjectResolver in start(...); the explicit RestSecurity.bootstrap()
    // call here demonstrates the V00.72 entry point and emits the
    // SecurityRuntime diagnostics banner. Mode = DEVELOPMENT so missing
    // resolver entries surface as warnings (the server has its own
    // resolver instance — the bootstrap is informational only here).
    com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime runtime =
        com.svenruppert.vaadin.security.dx.rest.bootstrap.RestSecurity.bootstrap()
            .mode(com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode.DEVELOPMENT)
            .subjectResolver(server.subjectResolver())
            .install();
    System.out.println(runtime.log());

    System.out.println("Demo REST server running on http://localhost:" + server.port());
    System.out.println("Default demo users: editor/editor, viewer/viewer "
        + "(admin/admin only when bootstrap is disabled).");
    System.out.println("Press Ctrl+C to stop.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }

  /** @return the server's RestSubjectResolver — for V00.72 bootstrap wiring */
  public com.svenruppert.vaadin.security.rest.RestSubjectResolver subjectResolver() {
    return this.subjectResolver;
  }
}
