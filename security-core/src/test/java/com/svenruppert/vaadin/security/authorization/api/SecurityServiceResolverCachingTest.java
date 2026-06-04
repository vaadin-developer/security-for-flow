/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.vaadin.security.authorization.api;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class SecurityServiceResolverCachingTest {

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  static final class StubAuthn implements AuthenticationService<String, String> {
    @Override public boolean checkCredentials(String c) { return false; }
    @Override public String loadSubject(String c) { return ""; }
    @Override public Class<String> subjectType() { return String.class; }
  }

  static final class StubAuthz implements AuthorizationService<String> {
    @Override public HasRoles rolesFor(String s) { return java.util.List::of; }
    @Override public HasPermissions permissionsFor(String s) {
      return java.util.List::of;
    }
  }

  // ── AuthenticationService ──────────────────────────────────────

  @Test
  @DisplayName("setAuthenticationService caches the service for subsequent calls")
  void setAuthenticationServiceCaches() {
    StubAuthn stub = new StubAuthn();
    SecurityServiceResolver.setAuthenticationService(stub);

    AuthenticationService<String, String> a =
        SecurityServiceResolver.authenticationService();
    AuthenticationService<String, String> b =
        SecurityServiceResolver.authenticationService();
    assertSame(stub, a, "first call must return the cached instance");
    assertSame(a, b, "second call must return the SAME instance, not re-resolve");
  }

  @Test
  @DisplayName("setAuthenticationService also feeds findAuthenticationService")
  void setAuthenticationServiceFeedsFind() {
    StubAuthn stub = new StubAuthn();
    SecurityServiceResolver.setAuthenticationService(stub);

    Optional<AuthenticationService<String, String>> r =
        SecurityServiceResolver.findAuthenticationService();
    assertTrue(r.isPresent());
    assertSame(stub, r.get());
  }

  @Test
  @DisplayName("setAuthenticationService(null) clears the cache so the next call re-resolves (and throws)")
  void setAuthenticationServiceNullClears() {
    SecurityServiceResolver.setAuthenticationService(new StubAuthn());
    SecurityServiceResolver.setAuthenticationService(null);
    // No SPI registered → reverting to ServiceLoader path → throws
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalStateException.class,
        SecurityServiceResolver::authenticationService);
  }

  // ── AuthorizationService ───────────────────────────────────────

  @Test
  @DisplayName("setAuthorizationService caches the service for subsequent calls")
  void setAuthorizationServiceCaches() {
    StubAuthz stub = new StubAuthz();
    SecurityServiceResolver.setAuthorizationService(stub);

    AuthorizationService<String> a = SecurityServiceResolver.authorizationService();
    AuthorizationService<String> b = SecurityServiceResolver.authorizationService();
    assertSame(stub, a);
    assertSame(a, b);
  }

  @Test
  @DisplayName("setAuthorizationService also feeds findAuthorizationService")
  void setAuthorizationServiceFeedsFind() {
    StubAuthz stub = new StubAuthz();
    SecurityServiceResolver.setAuthorizationService(stub);

    Optional<AuthorizationService<String>> r =
        SecurityServiceResolver.findAuthorizationService();
    assertTrue(r.isPresent());
    assertSame(stub, r.get());
  }

  @Test
  @DisplayName("setAuthorizationService(null) clears the cache so the next call re-resolves (and throws)")
  void setAuthorizationServiceNullClears() {
    SecurityServiceResolver.setAuthorizationService(new StubAuthz());
    SecurityServiceResolver.setAuthorizationService(null);
    org.junit.jupiter.api.Assertions.assertThrows(
        IllegalStateException.class,
        SecurityServiceResolver::authorizationService);
  }

  @Test
  @DisplayName("setAuthorizationService overrides existing cached value")
  void setAuthorizationServiceOverrides() {
    StubAuthz first = new StubAuthz();
    StubAuthz second = new StubAuthz();
    SecurityServiceResolver.setAuthorizationService(first);
    assertSame(first, SecurityServiceResolver.authorizationService());
    SecurityServiceResolver.setAuthorizationService(second);
    assertSame(second, SecurityServiceResolver.authorizationService(),
        "second set must replace the previous binding");
    assertFalse(SecurityServiceResolver.<String>authorizationService() == first);
  }
}
