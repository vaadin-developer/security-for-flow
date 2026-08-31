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
package eu.jsentinel.jcustos.authorization;

import eu.jsentinel.jcustos.authorization.navigation.NavigationAccessDecision;
import eu.jsentinel.jcustos.authorization.navigation.NavigationAccessDecisionService;
import eu.jsentinel.jcustos.authorization.navigation.NavigationJCustosContext;
import com.vaadin.flow.component.Component;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the {@link LoginListeners} cache semantics: {@code setLoginListener}
 * installs the instance, {@code loginListener()} / {@code findLoginListener()}
 * return that exact reference on subsequent calls, and {@code reset()}
 * clears the cache.
 */
@DisplayName("LoginListeners — cache + set/reset semantics")
class LoginListenersCacheTest {

  @AfterEach
  void clear() {
    LoginListeners.reset();
  }

  @Test
  @DisplayName("setLoginListener + loginListener() returns the exact installed instance")
  void setAndGet() {
    StubListener stub = new StubListener();
    LoginListeners.setLoginListener(stub);

    LoginListener<Object> resolved = LoginListeners.loginListener();
    assertSame(stub, resolved,
        "loginListener() must return the AtomicReference-cached instance");
  }

  @Test
  @DisplayName("setLoginListener + findLoginListener() returns Optional.of(stub)")
  void setAndFind() {
    StubListener stub = new StubListener();
    LoginListeners.setLoginListener(stub);

    Optional<LoginListener<Object>> resolved = LoginListeners.findLoginListener();
    assertTrue(resolved.isPresent(),
        "findLoginListener() must wrap the cached instance in Optional");
    assertSame(stub, resolved.get(),
        "findLoginListener() must return the AtomicReference-cached instance");
  }

  @Test
  @DisplayName("loginListener() returns the same instance on repeated calls (cache hit)")
  void loginListenerIsStable() {
    StubListener stub = new StubListener();
    LoginListeners.setLoginListener(stub);

    LoginListener<Object> first = LoginListeners.loginListener();
    LoginListener<Object> second = LoginListeners.loginListener();
    assertSame(first, second,
        "subsequent loginListener() calls must hit the cache");
  }

  @Test
  @DisplayName("reset() clears the cache so a subsequent set installs a fresh instance")
  void resetClearsCache() {
    StubListener first = new StubListener();
    LoginListeners.setLoginListener(first);
    assertSame(first, LoginListeners.loginListener());

    LoginListeners.reset();

    StubListener second = new StubListener();
    LoginListeners.setLoginListener(second);
    assertSame(second, LoginListeners.loginListener(),
        "after reset, setLoginListener must install the new instance into the cache");
  }

  @Test
  @DisplayName("setLoginListener(null) followed by findLoginListener() returns empty")
  void setNullClears() {
    LoginListeners.setLoginListener(new StubListener());
    LoginListeners.setLoginListener(null);

    assertTrue(LoginListeners.findLoginListener().isEmpty(),
        "setLoginListener(null) must replace the cached value with null");
  }

  // ── Fixture ───────────────────────────────────────────────────

  private static final class StubListener extends LoginListener<Object> {
    @Override public void notARestrictedTarget(Class<?> navigationTarget) { /* noop */ }
    @Override public Class<? extends LoginView> loginNavigationTarget() { return LoginView.class; }
    @Override public Class<? extends Component> defaultNavigationTarget() { return Component.class; }
  }

  // Suppress unused-import warnings; keep the imports tidy for readers
  // who want to inspect the abstract-method surface.
  @SuppressWarnings("unused")
  private static void unusedImportPin() {
    new NavigationAccessDecisionService();
    new NavigationJCustosContext(Object.class, true, true, true);
    NavigationAccessDecision.allowed();
  }
}
