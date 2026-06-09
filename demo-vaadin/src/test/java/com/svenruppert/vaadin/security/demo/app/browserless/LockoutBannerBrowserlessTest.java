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
package com.svenruppert.vaadin.security.demo.app.browserless;

import com.svenruppert.vaadin.security.authorization.LoginView;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptContext;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptDecision;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.demo.app.security.bootstrap.BootstrapWiring;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.vaadin.security.demo.app.views.MyLoginView;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless adapter test for the lockout banner in
 * {@link MyLoginView}. After a failed login attempt, the view re-queries
 * {@link LoginAttemptPolicy#beforeAttempt(LoginAttemptContext)} and, when
 * it now reports {@link LoginAttemptDecision.LockedOut}, surfaces a red
 * Notification with the remaining lockout time and failure count instead
 * of the generic "Credentials not accepted" toast.
 */
@DisplayName("MyLoginView — lockout banner via BrowserlessTest")
class LockoutBannerBrowserlessTest extends BrowserlessTest {

  @BeforeEach
  void setUp() throws Exception {
    // The Vaadin demo's BootstrapWiring is a singleton that runs
    // enableBootstrapMode() (which wipes seeded admins) at first access.
    // For tests we want bootstrap OFF, so the LoginView renders without
    // forwarding to /setup. Two steps:
    //   (1) ask for DISABLED mode via system property, and
    //   (2) drop any cached singleton so the next instance() call
    //       picks up the new property.
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();

    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    // Seed an admin so the directory reports hasAnyAdministrator(), even
    // though with DISABLED mode the bootstrap flow no longer cares.
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    // Stub policy: always locked out for any attempt.
    JSentinelServiceResolver.setLoginAttemptPolicy(new AlwaysLockedPolicy(
        Duration.ofMinutes(5), 7));
  }

  /** Resets the {@link BootstrapWiring#current} static singleton via reflection. */
  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("LockedOut decision surfaces in a Notification with seconds + failure count")
  void lockoutNotification() {
    navigate(MyLoginView.class);

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("admin");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    Notification notification = $(Notification.class).first();
    String message = test(notification).getText();
    assertTrue(message.contains("Account locked"),
        "Notification must announce the lockout: " + message);
    assertTrue(message.contains("7"),
        "Notification must include the failure count from the policy: " + message);
    assertTrue(message.contains("5 min"),
        "Notification must include the formatted remaining time: " + message);
  }

  private static final class AlwaysLockedPolicy implements LoginAttemptPolicy {
    private final Duration remaining;
    private final int failedAttempts;

    AlwaysLockedPolicy(Duration remaining, int failedAttempts) {
      this.remaining = remaining;
      this.failedAttempts = failedAttempts;
    }

    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) {
      return LoginAttemptDecision.lockedOut(remaining, failedAttempts);
    }

    @Override public void recordSuccess(LoginAttemptContext ctx) { }

    @Override public void recordFailure(LoginAttemptContext ctx) { }
  }
}
