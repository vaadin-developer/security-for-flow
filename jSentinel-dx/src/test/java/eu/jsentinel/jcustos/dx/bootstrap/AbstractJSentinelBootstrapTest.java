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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.dx.internal.AbstractJSentinelBootstrap;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapMode;
import eu.jsentinel.jcustos.test.FakeAuthenticationService;
import eu.jsentinel.jcustos.test.FakeAuthorizationService;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AbstractJSentinelBootstrapTest {

  /** Test-only concrete subclass that does not override install(). */
  static final class TestBootstrap
      extends AbstractJSentinelBootstrap<TestBootstrap> {
    BootstrapStateAccessor stateAccessor() {
      return new BootstrapStateAccessor(state);
    }
  }

  /** Minimal read accessor so tests can assert against the package-internal state. */
  static final class BootstrapStateAccessor {
    final eu.jsentinel.jcustos.dx.internal.BootstrapState state;
    BootstrapStateAccessor(eu.jsentinel.jcustos.dx.internal.BootstrapState s) {
      this.state = s;
    }
  }

  @Test
  void fluentChainReturnsConcreteBuilder() {
    TestBootstrap b = new TestBootstrap();
    FakeAuthenticationService<String, String> authn = FakeAuthenticationService.forType(String.class);
    FakeAuthorizationService<String> authz = new FakeAuthorizationService<>();

    TestBootstrap result = b
        .authentication(authn)
        .authorization(authz)
        .mode(JSentinelBootstrapMode.PRODUCTION);

    assertSame(b, result, "fluent chain must return concrete builder type");
  }

  @Test
  void subBuilderCallbacksInvokedExactlyOnce() {
    TestBootstrap b = new TestBootstrap();
    AtomicInteger auditCalls = new AtomicInteger();
    AtomicInteger sessionCalls = new AtomicInteger();
    AtomicInteger policyCalls = new AtomicInteger();
    AtomicInteger credentialCalls = new AtomicInteger();

    b.audit(a -> { auditCalls.incrementAndGet(); a.ringBuffer(256); })
     .sessions(s -> { sessionCalls.incrementAndGet(); s.timeout(Duration.ofMinutes(5)); })
     .policies(p -> {
       policyCalls.incrementAndGet();
       p.register(eu.jsentinel.jcustos.policy.api.Policy.named("dummy")
           .allowIf(c -> true).deny("none").build());
     })
     .credentials(c -> { credentialCalls.incrementAndGet(); c.pbkdf2Defaults(); });

    assertEquals(1, auditCalls.get());
    assertEquals(1, sessionCalls.get());
    assertEquals(1, policyCalls.get());
    assertEquals(1, credentialCalls.get());

    assertTrue(b.stateAccessor().state.auditConfigured());
    assertTrue(b.stateAccessor().state.sessionsConfigured());
    assertTrue(b.stateAccessor().state.policiesConfigured());
    assertTrue(b.stateAccessor().state.credentialsConfigured());
  }

  @Test
  void installInBaseClassThrowsUnsupported() {
    TestBootstrap b = new TestBootstrap();
    assertThrows(UnsupportedOperationException.class, b::install);
  }

  @Test
  void defaultModeIsCommunityDefaults() {
    TestBootstrap b = new TestBootstrap();
    assertEquals(JSentinelBootstrapMode.COMMUNITY_DEFAULTS, b.stateAccessor().state.mode());
  }

  @Test
  void modeCanBeSet() {
    TestBootstrap b = new TestBootstrap().mode(JSentinelBootstrapMode.STRICT);
    assertEquals(JSentinelBootstrapMode.STRICT, b.stateAccessor().state.mode());
  }

  @Test
  void nullArgumentsRejected() {
    TestBootstrap b = new TestBootstrap();
    assertThrows(NullPointerException.class, () -> b.authentication(null));
    assertThrows(NullPointerException.class, () -> b.authorization(null));
    assertThrows(NullPointerException.class, () -> b.audit(null));
    assertThrows(NullPointerException.class, () -> b.sessions(null));
    assertThrows(NullPointerException.class, () -> b.policies(null));
    assertThrows(NullPointerException.class, () -> b.roles(null));
    assertThrows(NullPointerException.class, () -> b.credentials(null));
    assertThrows(NullPointerException.class, () -> b.mode(null));
  }
}
