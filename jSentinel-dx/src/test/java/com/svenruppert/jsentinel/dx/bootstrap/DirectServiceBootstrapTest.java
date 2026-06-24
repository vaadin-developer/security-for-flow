/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.dx.bootstrap;

import com.svenruppert.jsentinel.audit.NoopJSentinelAuditService;
import com.svenruppert.jsentinel.authentication.ApiKeyAuthenticationService;
import com.svenruppert.jsentinel.authentication.ApiKeyStore;
import com.svenruppert.jsentinel.authentication.InMemoryApiKeyStore;
import com.svenruppert.jsentinel.authentication.InMemoryRefreshTokenStore;
import com.svenruppert.jsentinel.credential.token.Sha256TokenHasher;
import com.svenruppert.jsentinel.credential.token.TokenHasher;
import com.svenruppert.jsentinel.authentication.TokenService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.bruteforce.InMemoryLoginAttemptPolicy;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptPolicy;
import com.svenruppert.jsentinel.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import com.svenruppert.jsentinel.logout.LogoutService;
import com.svenruppert.jsentinel.ratelimiting.InMemoryRateLimitPolicy;
import com.svenruppert.jsentinel.ratelimiting.InMemoryRateLimitStore;
import com.svenruppert.jsentinel.ratelimiting.RateLimitPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("V00.74 direct-service builder methods")
class DirectServiceBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".logout(svc) registers via JSentinelServiceResolver.setLogoutService(...)")
  void logoutWiresResolver() {
    LogoutService svc = new RecordingLogoutService();
    JSentinelRuntime runtime = new TestBootstrap()
        .logout(svc)
        .install();
    assertSame(svc, JSentinelServiceResolver.findLogoutService().orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> LogoutService.class.equals(s.spi())));
  }

  @Test
  @DisplayName(".bruteForce(policy) registers via JSentinelServiceResolver.setLoginAttemptPolicy(...)")
  void bruteForceWiresResolver() {
    LoginAttemptPolicy policy = new InMemoryLoginAttemptPolicy();
    JSentinelRuntime runtime = new TestBootstrap()
        .bruteForce(policy)
        .install();
    assertSame(policy, JSentinelServiceResolver.findLoginAttemptPolicy().orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> LoginAttemptPolicy.class.equals(s.spi())));
  }

  @Test
  @DisplayName(".rateLimit(policy) is recorded-not-wired: INFO warning, NOT a registered service (R029)")
  void rateLimitDxStateOnly() {
    RateLimitPolicy policy = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(),
        new NoopJSentinelAuditService(),
        200, Duration.ofMinutes(1));
    JSentinelRuntime runtime = new TestBootstrap()
        .rateLimit(policy)
        .install();
    // R029: must NOT masquerade as an actively-wired service.
    assertFalse(runtime.services().stream()
        .anyMatch(s -> RateLimitPolicy.class.equals(s.spi())),
        "an unwired DX feature must not appear as a registered service");
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "dx/rate-limit-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.INFO),
        "an unwired DX feature must surface as an explicit INFO");
  }

  @Test
  @DisplayName(".apiKeys(svc) is recorded-not-wired: INFO warning, NOT a registered service (R029)")
  void apiKeysDxStateOnly() {
    ApiKeyStore store = new InMemoryApiKeyStore();
    TokenHasher hasher = new Sha256TokenHasher();
    ApiKeyAuthenticationService svc = new ApiKeyAuthenticationService(
        store, hasher, new NoopJSentinelAuditService());
    JSentinelRuntime runtime = new TestBootstrap()
        .apiKeys(svc)
        .install();
    assertFalse(runtime.services().stream()
        .anyMatch(s -> ApiKeyAuthenticationService.class.equals(s.spi())));
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "dx/api-keys-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.INFO));
  }

  @Test
  @DisplayName(".refreshTokens(svc) is recorded-not-wired: INFO warning, NOT a registered service (R029)")
  void refreshTokensDxStateOnly() {
    TokenService svc = new TokenService(
        new InMemoryRefreshTokenStore(),
        new Sha256TokenHasher(),
        new NoopJSentinelAuditService());
    JSentinelRuntime runtime = new TestBootstrap()
        .refreshTokens(svc)
        .install();
    assertFalse(runtime.services().stream()
        .anyMatch(s -> TokenService.class.equals(s.spi())));
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "dx/refresh-tokens-recorded-not-wired".equals(w.code())
            && w.severity() == Severity.INFO));
  }

  @Test
  @DisplayName("resolver-wired services register; recorded-not-wired features surface as INFO (R029)")
  void allFiveTogether() {
    LogoutService logout = new RecordingLogoutService();
    LoginAttemptPolicy bf = new InMemoryLoginAttemptPolicy();
    RateLimitPolicy rl = new InMemoryRateLimitPolicy(
        new InMemoryRateLimitStore(), new NoopJSentinelAuditService(),
        50, Duration.ofMinutes(1));
    TokenHasher hasher = new Sha256TokenHasher();
    ApiKeyAuthenticationService ak = new ApiKeyAuthenticationService(
        new InMemoryApiKeyStore(), hasher, new NoopJSentinelAuditService());
    TokenService ts = new TokenService(
        new InMemoryRefreshTokenStore(), hasher, new NoopJSentinelAuditService());

    JSentinelRuntime runtime = new TestBootstrap()
        .logout(logout)
        .bruteForce(bf)
        .rateLimit(rl)
        .apiKeys(ak)
        .refreshTokens(ts)
        .install();

    // Only the two genuinely resolver-wired services register.
    assertEquals(2, runtime.services().stream()
        .filter(s -> s.spi() == LogoutService.class
            || s.spi() == LoginAttemptPolicy.class)
        .count(),
        "only resolver-wired services (logout + brute-force) must register");
    assertEquals(0, runtime.services().stream()
        .filter(s -> s.spi() == RateLimitPolicy.class
            || s.spi() == ApiKeyAuthenticationService.class
            || s.spi() == TokenService.class)
        .count(),
        "recorded-not-wired features must NOT register as services");
    // The three recorded-not-wired features each surface as an INFO.
    assertEquals(3, runtime.warnings().stream()
        .filter(w -> w.severity() == Severity.INFO
            && w.code().endsWith("-recorded-not-wired"))
        .count(),
        "rateLimit / apiKeys / refreshTokens must each surface as an INFO");
  }

  @Test
  @DisplayName("null arguments are rejected")
  void nullsRejected() {
    assertThrows(NullPointerException.class, () -> new TestBootstrap().logout(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().bruteForce(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().rateLimit(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().apiKeys(null));
    assertThrows(NullPointerException.class, () -> new TestBootstrap().refreshTokens(null));
  }

  // ── adapter test double ──────────────────────────────────────────

  private static final class TestBootstrap
      extends AbstractJSentinelBootstrap<TestBootstrap> {
    @Override
    public JSentinelRuntime install() {
      List<RegisteredJSentinelService> services = new ArrayList<>();
      List<JSentinelBootstrapWarning> warnings = new ArrayList<>();
      applyDirectServiceConfiguration(services, warnings);
      JSentinelBootstrapMode mode = state.mode();
      if (mode == JSentinelBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new JSentinelBootstrapException(warnings);
      }
      return new JSentinelRuntime(services, warnings, mode);
    }
  }

  /** Minimal LogoutService impl for tests — no-op, just lets us register a real instance. */
  private static final class RecordingLogoutService implements LogoutService {
    @Override public void logout(com.svenruppert.jsentinel.logout.SubjectId subjectId,
                                  com.svenruppert.jsentinel.logout.LogoutScope scope) { }
    @Override public void addListener(com.svenruppert.jsentinel.logout.LogoutListener listener) { }
    @Override public void removeListener(com.svenruppert.jsentinel.logout.LogoutListener listener) { }
  }
}
