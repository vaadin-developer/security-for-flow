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
package com.svenruppert.jsentinel.authorization;

import com.svenruppert.jsentinel.audit.SessionInvalidated;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.session.SessionContext;
import com.svenruppert.jsentinel.session.SessionDecision;
import com.svenruppert.jsentinel.session.SessionMetadata;
import com.svenruppert.jsentinel.session.SessionPolicy;
import com.svenruppert.jsentinel.session.SessionPolicyDecision;
import com.svenruppert.jsentinel.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the order in which {@link LoginView} consults its collaborators:
 * <ol>
 *   <li>{@code checkCredentials()} (subclass)</li>
 *   <li>{@code notifyOnLogin()} → {@link SessionPolicy#onLogin}</li>
 *   <li>{@code navigateToApp()} (subclass)</li>
 * </ol>
 * Plus the failure path: {@code checkCredentials} → {@code reactOnFailedLogin}.
 * <p>
 * A subclass records every callback into a shared call-log; the
 * {@link RecordingSessionPolicy} appends its own entry on
 * {@code onLogin}. The test then compares the log against the expected
 * sequence — a regression in either ordering or the conditional
 * dispatch would shuffle / remove entries.
 */
@DisplayName("LoginView — policy ordering on success / failure")
class LoginViewPolicyOrderingTest extends BrowserlessTest {

  private final List<String> calls = new ArrayList<>();
  private final RecordingSessionPolicy sessionPolicy = new RecordingSessionPolicy(calls);
  private final RecordingAuditSink audit = new RecordingAuditSink();

  @BeforeEach
  void wire() {
    JSentinelServiceResolver.resetAll();
    JSentinelServiceResolver.setSessionPolicy(sessionPolicy);
    JSentinelServiceResolver.setJSentinelAuditService(audit);
    calls.clear();
    OrderingLoginView.acceptCredentials = true;
    OrderingLoginView.callLog = calls;
  }

  @AfterEach
  void cleanUp() {
    JSentinelServiceResolver.resetAll();
    OrderingLoginView.callLog = null;
  }

  @Test
  @DisplayName("Success path: checkCredentials → SessionPolicy.onLogin → navigateToApp")
  void successOrdering() {
    OrderingLoginView.acceptCredentials = true;
    navigate(OrderingLoginView.class);

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("alice");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("alice");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    assertEquals(
        List.of("checkCredentials", "SessionPolicy.onLogin", "navigateToApp"),
        calls,
        "the success path must consult collaborators in this exact order");

    assertFalse(calls.contains("reactOnFailedLogin"),
        "reactOnFailedLogin must not fire on the success path");
  }

  @Test
  @DisplayName("Failure path: checkCredentials → reactOnFailedLogin, SessionPolicy.onLogin NOT called")
  void failureOrdering() {
    OrderingLoginView.acceptCredentials = false;
    navigate(OrderingLoginView.class);

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("alice");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("WRONG");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    assertEquals(
        List.of("checkCredentials", "reactOnFailedLogin"),
        calls,
        "the failure path must consult only checkCredentials + reactOnFailedLogin");

    assertFalse(calls.contains("SessionPolicy.onLogin"),
        "SessionPolicy.onLogin must NOT fire when credentials are rejected");
    assertFalse(calls.contains("navigateToApp"),
        "navigateToApp must NOT fire when credentials are rejected");
  }

  @Test
  @DisplayName("Invalidate from onLogin still keeps the order, plus emits SessionInvalidated before navigateToApp")
  void invalidateOrdering() {
    OrderingLoginView.acceptCredentials = true;
    sessionPolicy.nextDecision = new SessionDecision.Invalidate(
        "TestRotation", "/login");

    navigate(OrderingLoginView.class);

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("alice");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("alice");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    // The reinitialize + audit happen synchronously inside notifyOnLogin,
    // i.e. between SessionPolicy.onLogin and navigateToApp.
    int onLoginIndex = calls.indexOf("SessionPolicy.onLogin");
    int navIndex = calls.indexOf("navigateToApp");
    assertTrue(onLoginIndex >= 0 && navIndex > onLoginIndex,
        "SessionPolicy.onLogin must fire before navigateToApp; got: " + calls);

    assertTrue(audit.events().stream().anyMatch(SessionInvalidated.class::isInstance),
        "an Invalidate decision must publish a SessionInvalidated audit event; got: " + audit.events());
  }

  // ── Fixtures ──────────────────────────────────────────────────

  /**
   * Test-only LoginView that records every framework callback into a
   * shared call-log so the test can pin the order.
   */
  @Route("test/ordering-login")
  public static class OrderingLoginView extends LoginView {
    static List<String> callLog;
    static boolean acceptCredentials = true;

    @Override public boolean checkCredentials() {
      if (callLog != null) callLog.add("checkCredentials");
      return acceptCredentials;
    }

    @Override public void navigateToApp() {
      if (callLog != null) callLog.add("navigateToApp");
    }

    @Override public void reactOnFailedLogin() {
      if (callLog != null) callLog.add("reactOnFailedLogin");
    }
  }

  static final class RecordingSessionPolicy implements SessionPolicy<Object> {
    private final List<String> log;
    SessionDecision nextDecision = SessionDecision.Continue.INSTANCE;

    RecordingSessionPolicy(List<String> log) {
      this.log = log;
    }

    @Override public SessionDecision onLogin(SessionContext<Object> context) {
      log.add("SessionPolicy.onLogin");
      return nextDecision;
    }

    @Override public SessionDecision beforeNavigation(SessionContext<Object> context) {
      return SessionDecision.Continue.INSTANCE;
    }

    @Override public SessionPolicyDecision evaluate(SessionMetadata metadata) {
      return SessionPolicyDecision.active();
    }
  }

}
