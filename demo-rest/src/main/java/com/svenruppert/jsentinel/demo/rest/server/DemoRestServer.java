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
package com.svenruppert.jsentinel.demo.rest.server;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.accountlifecycle.InMemoryPasswordResetTokenStore;
import com.svenruppert.jsentinel.accountlifecycle.LoggingNotificationSender;
import com.svenruppert.jsentinel.accountlifecycle.PasswordResetService;
import com.svenruppert.jsentinel.authentication.ApiKeyAuthenticationService;
import com.svenruppert.jsentinel.authentication.ApiKeyStore;
import com.svenruppert.jsentinel.authentication.InMemoryApiKeyStore;
import com.svenruppert.jsentinel.authentication.InMemoryRefreshTokenStore;
import com.svenruppert.jsentinel.authentication.TokenService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptConfiguration;
import com.svenruppert.jsentinel.credential.password.PasswordHashingService;
import com.svenruppert.jsentinel.credential.password.PasswordHashingServices;
import com.svenruppert.jsentinel.credential.token.Sha256TokenHasher;
import com.svenruppert.jsentinel.dx.rest.bootstrap.RestSecurity;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.ratelimiting.InMemoryRateLimitPolicy;
import com.svenruppert.jsentinel.ratelimiting.InMemoryRateLimitStore;
import com.svenruppert.jsentinel.ratelimiting.RateLimitPolicy;

import java.time.Duration;
import com.svenruppert.jsentinel.logout.SubjectClearingLogoutService;
import com.svenruppert.jsentinel.authorization.api.SubjectStore;
import com.svenruppert.jsentinel.bootstrap.BootstrapConfiguration;
import com.svenruppert.jsentinel.bootstrap.BootstrapMode;
import com.svenruppert.jsentinel.bootstrap.BootstrapStartup;
import com.svenruppert.jsentinel.bootstrap.BootstrapStateService;
import com.svenruppert.jsentinel.bootstrap.BootstrapTokenGenerator;
import com.svenruppert.jsentinel.bootstrap.BootstrapTokenOutput;
import com.svenruppert.jsentinel.bootstrap.BootstrapTokenStore;
import com.svenruppert.jsentinel.bootstrap.ConsoleBootstrapTokenOutput;
import com.svenruppert.jsentinel.bootstrap.FileBootstrapTokenOutput;
import com.svenruppert.jsentinel.bootstrap.FileBootstrapTokenStore;
import com.svenruppert.jsentinel.bootstrap.InMemoryBootstrapTokenStore;
import com.svenruppert.jsentinel.bootstrap.InitialAdminBootstrapService;
import com.svenruppert.jsentinel.bootstrap.MinimumLengthPasswordPolicy;
import com.svenruppert.jsentinel.bruteforce.InMemoryLoginAttemptPolicy;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptPolicy;
import com.svenruppert.jsentinel.demo.rest.domain.DemoDocumentStore;
import com.svenruppert.jsentinel.demo.rest.domain.DemoOwnedDocumentStore;
import com.svenruppert.jsentinel.demo.rest.domain.DemoRolePermissionMapping;
import com.svenruppert.jsentinel.demo.rest.domain.DemoUser;
import com.svenruppert.jsentinel.demo.rest.domain.DemoUserStore;
import com.svenruppert.jsentinel.demo.rest.shared.DemoEndpoints;
import com.svenruppert.jsentinel.policy.impl.InMemoryPolicyRegistry;
import com.svenruppert.jsentinel.policy.impl.InMemoryResourceResolverRegistry;
import com.svenruppert.jsentinel.policy.spi.PolicyRegistry;
import com.svenruppert.jsentinel.policy.spi.ResourceResolverRegistry;
import com.svenruppert.jsentinel.rest.RestJSentinelVersionFilter;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
import com.svenruppert.jsentinel.session.InMemoryJSentinelVersionStore;
import com.svenruppert.jsentinel.session.JSentinelVersionEnforcer;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;
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
  private final RestSubjectResolver subjectResolver;

  private DemoRestServer(HttpServer httpServer, int port) {
    this(httpServer, port, null);
  }

  private DemoRestServer(HttpServer httpServer, int port,
                         RestSubjectResolver subjectResolver) {
    this.httpServer = httpServer;
    this.port = port;
    this.subjectResolver = subjectResolver;
  }

  public static DemoRestServer start(int port) throws IOException {
    return start(port, DemoBootstrapEnvironment.fromEnvironment(),
        new InMemoryLoginAttemptPolicy(),
        new InMemoryLoginAttemptPolicy(
            LoginAttemptConfiguration.strictBootstrap(),
            java.time.Clock.systemUTC(),
            null));
  }

  public static DemoRestServer start(int port, BootstrapConfiguration bootstrapConfig) throws IOException {
    return start(port, bootstrapConfig,
        new InMemoryLoginAttemptPolicy(),
        new InMemoryLoginAttemptPolicy(
            LoginAttemptConfiguration.strictBootstrap(),
            java.time.Clock.systemUTC(),
            null));
  }

  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     LoginAttemptPolicy loginAttemptPolicy) throws IOException {
    return start(port, bootstrapConfig, loginAttemptPolicy,
        new InMemoryLoginAttemptPolicy(
            LoginAttemptConfiguration.strictBootstrap(),
            java.time.Clock.systemUTC(),
            null));
  }

  public static DemoRestServer start(int port,
                                     BootstrapConfiguration bootstrapConfig,
                                     LoginAttemptPolicy loginAttemptPolicy,
                                     LoginAttemptPolicy bootstrapAttemptPolicy) throws IOException {
    boolean bootstrapMode = bootstrapConfig.mode() != BootstrapMode.DISABLED;
    PasswordHashingService hashingService =
        PasswordHashingServices.defaults();
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
        JSentinelServiceResolver.securityAuditService());
    DemoSubjectResolver resolver = new DemoSubjectResolver(
        tokens, mapping, apiKeyAuth);
    DemoOperationRegistry registry = new DemoOperationRegistry();
    JSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    // PasswordResetService requires a *deterministic* hasher so the
    // token-hash → record lookup actually matches. The SPI-resolved
    // PasswordHasher (PBKDF2 / Argon2id) is salted by design and would
    // produce a different hash every call — wrong tool for this job.
    PasswordResetService passwordResetService = new PasswordResetService(
        new InMemoryPasswordResetTokenStore(),
        new Sha256TokenHasher(),
        JSentinelServiceResolver.securityAuditService(),
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
        JSentinelServiceResolver.securityAuditService(),
        200,
        Duration.ofMinutes(1));
    // V00.70 Phase-7b — rotating refresh tokens. Uses the same
    // Sha256TokenHasher as API keys (deterministic lookup) and a
    // dedicated InMemoryRefreshTokenStore.
    TokenService tokenService = new TokenService(
        new InMemoryRefreshTokenStore(),
        apiKeyHasher,
        JSentinelServiceResolver.securityAuditService());
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
    ResourceResolverRegistry resourceRegistry = new InMemoryResourceResolverRegistry();

    // V00.73 fluent bootstrap. Replaces the V00.71 JSentinelServiceResolver
    // direct-set calls for PolicyRegistry / ResourceResolverRegistry /
    // JSentinelVersionStore and surfaces the V00.71 password-hashing pipeline.
    //
    // .audit(...) is intentionally NOT used here: ApiKeyAuthenticationService,
    // TokenService and the demo's PasswordResetService capture
    // JSentinelServiceResolver.securityAuditService() at construction time
    // (lines above), so replacing the audit service at install() would
    // leave those references pointing at the previous instance. Demos
    // that have full control over construction order — like demo-vaadin
    // and demo-standalone — can use .audit(...) freely.
    JSentinelRuntime runtime =
        RestSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.DEVELOPMENT)
            .subjectResolver(resolver)
            .credentials(c -> c.hashing(hashingService))
            .sessions(s -> s.securityVersion(versionStore))
            .policies(p -> p
                .registry(policyRegistry)
                .resourceRegistry(resourceRegistry)
                .register(DemoPolicies.documentOwnerOrAdmin())
                .resourceResolver(new DemoOwnedDocumentResolver(ownedDocumentStore)))
            .install();
    HasLogger.staticLogger().info("{}", runtime.log());

    JSentinelVersionEnforcer versionEnforcer = new JSentinelVersionEnforcer(
        versionStore, JSentinelServiceResolver.securityAuditService());
    RestJSentinelVersionFilter versionFilter = new RestJSentinelVersionFilter(
        resolver, versionEnforcer);

    SubjectClearingLogoutService<DemoUser> logoutService = new SubjectClearingLogoutService<>(
        NoopSubjectStore.INSTANCE, DemoUser.class, tokens, null);
    logoutService.addListener((subjectId, sessionId, scope) -> {
      if (sessionId != null) {
        tokens.revoke(sessionId);
      }
    });
    JSentinelServiceResolver.setLogoutService(logoutService);

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
    // V00.73: the RestSecurity.bootstrap() chain that prints the
    // JSentinelRuntime diagnostic banner now lives inside start(...) —
    // every demo entry point (main, tests) sees the same wiring.
    DemoRestServer server = start(port);
    System.out.println("Demo REST server running on http://localhost:" + server.port());
    System.out.println("Default demo users: editor/editor, viewer/viewer "
        + "(admin/admin only when bootstrap is disabled).");
    System.out.println("Press Ctrl+C to stop.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }

  /** @return the server's RestSubjectResolver — for V00.72 bootstrap wiring */
  public RestSubjectResolver subjectResolver() {
    return this.subjectResolver;
  }
}