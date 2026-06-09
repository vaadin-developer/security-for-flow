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

import com.svenruppert.jsentinel.authentication.PasswordHasher;
import com.svenruppert.jsentinel.authentication.Pbkdf2PasswordHasher;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.credential.password.PasswordHashingService;
import com.svenruppert.jsentinel.credential.password.PasswordHashingServices;
import com.svenruppert.jsentinel.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("CredentialBootstrap real surface (V00.73)")
class CredentialBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".passwordHasher(...) registers via legacy resolver setter")
  void passwordHasherWiresLegacyResolver() {
    // JSentinelServiceResolver.findPasswordHashingService() treats
    // Pbkdf2PasswordHasher as the default fallback and returns empty.
    // Use a non-PBKDF2 stub to verify the registration.
    PasswordHasher hasher = new RecordingPasswordHasher();
    JSentinelRuntime runtime = new TestBootstrap()
        .credentials(c -> c.passwordHasher(hasher))
        .install();
    assertSame(hasher, JSentinelServiceResolver.findPasswordHashingService().orElseThrow());
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHasher.class.equals(s.spi())));
  }

  /** Non-Pbkdf2 PasswordHasher so findPasswordHashingService returns it. */
  private static final class RecordingPasswordHasher implements PasswordHasher {
    @Override public String hash(char[] password) { return "stub:" + new String(password); }
    @Override public boolean verify(char[] password, String hashed) {
      return hashed != null && hashed.equals("stub:" + new String(password));
    }
  }

  @Test
  @DisplayName(".hashing(...) appears in runtime but is NOT passed to the legacy setter")
  void hashingServiceNotWiredThroughLegacy() {
    PasswordHashingService pipeline = PasswordHashingServices.defaults();
    JSentinelRuntime runtime = new TestBootstrap()
        .credentials(c -> c.hashing(pipeline))
        .install();
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHashingService.class.equals(s.spi())));
    assertFalse(JSentinelServiceResolver.findPasswordHashingService().isPresent(),
        "V00.71 PasswordHashingService must never be stuffed into the legacy PasswordHasher setter");
  }

  @Test
  @DisplayName(".pbkdf2Defaults() sets BOTH the legacy hasher and the V00.71 pipeline")
  void pbkdf2DefaultsSetsBothWorlds() {
    JSentinelRuntime runtime = new TestBootstrap()
        .credentials(c -> c.pbkdf2Defaults())
        .install();
    // findPasswordHashingService() returns empty for Pbkdf2 (treated as
    // default fallback) — verify legacy entry through runtime.services()
    // and pipeline entry the same way.
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHasher.class.equals(s.spi())
            && Pbkdf2PasswordHasher.class.equals(s.impl())));
    assertTrue(runtime.services().stream()
        .anyMatch(s -> PasswordHashingService.class.equals(s.spi())));
  }

  @Test
  @DisplayName(".modern() with security-crypto-bc on classpath wires the BC pipeline")
  void modernUsesBouncyCastleWhenAvailable() {
    // security-crypto-bc IS on the test classpath via the security-dx
    // test dependency tree, so this verifies the happy path.
    JSentinelRuntime runtime = new TestBootstrap()
        .credentials(c -> c.modern())
        .install();
    boolean pipelinePresent = runtime.services().stream()
        .anyMatch(s -> PasswordHashingService.class.equals(s.spi()));
    assertTrue(pipelinePresent, "modern() should register a PasswordHashingService");
  }

  @Test
  @DisplayName(".credentialStore(...) without .hashing(...) is fine; only change/reset trigger missing-hashing")
  void credentialStoreAloneIsOk() {
    JSentinelRuntime runtime = new TestBootstrap()
        .credentials(c -> c.credentialStore(
            new com.svenruppert.jsentinel.credential.store.InMemoryCredentialStore()))
        .install();
    assertFalse(runtime.warnings().stream()
        .anyMatch(w -> "credentials/missing-hashing".equals(w.code())),
        ".credentialStore() alone must not trigger missing-hashing");
    assertTrue(runtime.services().stream()
        .anyMatch(s -> com.svenruppert.jsentinel.credential.store.CredentialStore.class.equals(s.spi())));
  }

  @Test
  @DisplayName("RoleBootstrap-style API check: V00.73 CredentialBootstrap has the 8 documented methods")
  void apiSurface() {
    List<String> methodNames = java.util.Arrays.stream(CredentialBootstrap.class.getMethods())
        .map(java.lang.reflect.Method::getName)
        .sorted()
        .toList();
    assertEquals(
        List.of("credentialStore", "hashing", "modern", "passwordChange",
            "passwordHasher", "passwordReset", "pbkdf2Defaults", "pepper"),
        methodNames);
  }

  // ── adapter test double ──────────────────────────────────────────

  private static final class TestBootstrap
      extends AbstractJSentinelBootstrap<TestBootstrap> {
    @Override
    public JSentinelRuntime install() {
      List<RegisteredJSentinelService> services = new ArrayList<>();
      List<JSentinelBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(AdapterKind.VAADIN, services, warnings);
      applyRoleConfiguration(services, warnings);
      applyCredentialConfiguration(services, warnings);
      JSentinelBootstrapMode mode = state.mode();
      if (mode == JSentinelBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new JSentinelBootstrapException(warnings);
      }
      return new JSentinelRuntime(services, warnings, mode);
    }
  }
}
