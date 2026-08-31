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
package eu.jsentinel.jcustos.demo.app.browserless;

import eu.jsentinel.jcustos.audit.SessionInvalidated;
import eu.jsentinel.jcustos.authorization.LoginView;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.demo.app.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.app.security.model.DemoUserDirectoryProvider;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.demo.app.views.MyLoginView;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionPolicy;
import eu.jsentinel.jcustos.test.RecordingAuditSink;
import com.vaadin.browserless.BrowserlessTest;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Browserless adapter test for B3 — session-id rotation honour after
 * a successful login.
 * <p>
 * Wires a custom {@link SessionPolicy} whose {@code onLogin(...)}
 * returns a {@link SessionDecision.Invalidate}. After the credentials
 * pass, {@code LoginView.notifyOnLogin(...)} is expected to:
 * <ul>
 *   <li>call {@code VaadinService.reinitializeSession(...)} (verified
 *       indirectly via the audit emit below — the audit fires only after
 *       the reinitialize call has succeeded), and</li>
 *   <li>publish a {@link SessionInvalidated} event with reason
 *       {@code "RotationAfterLogin"}.</li>
 * </ul>
 */
@DisplayName("MyLoginView — session-id rotation honour (B3)")
class SessionRotationBrowserlessTest extends BrowserlessTest {

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final AtomicReference<SessionContext<Object>> capturedOnLoginContext = new AtomicReference<>();

  @BeforeEach
  void setUp() throws Exception {
    System.setProperty("security.bootstrap.mode", "DISABLED");
    resetBootstrapWiringSingleton();

    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));

    // Bypass brute-force checks — credentials must be accepted.
    JCustosServiceResolver.setLoginAttemptPolicy(new AllowingPolicy());

    // Custom SessionPolicy: capture the onLogin context, return Invalidate
    // so the LoginView triggers the B3 rotation path.
    JCustosServiceResolver.setSessionPolicy(new RotatingSessionPolicy(capturedOnLoginContext));

    JCustosServiceResolver.setJCustosAuditService(audit);
  }

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("Invalidate from onLogin triggers reinitializeSession + SessionInvalidated audit")
  void rotationEmitsSessionInvalidated() {
    navigate(MyLoginView.class);

    test($view(TextField.class).id(LoginView.TF_USERNAME_ID)).setValue("admin");
    test($view(PasswordField.class).id(LoginView.PF_PASSWORD_ID)).setValue("admin");
    test($view(Button.class).id(LoginView.BTN_LOGIN_ID)).click();

    assertNotNull(capturedOnLoginContext.get(),
        "SessionPolicy.onLogin must be called after credentials succeed");

    SessionInvalidated event = audit.events().stream()
        .filter(SessionInvalidated.class::isInstance)
        .map(SessionInvalidated.class::cast)
        .findFirst()
        .orElseThrow(() -> new AssertionError(
            "expected one SessionInvalidated event for the rotation; got: " + audit.events()));

    assertEquals("RotationAfterLogin", event.reason(),
        "SessionInvalidated.reason must propagate from the SessionDecision.Invalidate");
    assertTrue(event.sessionId() == null || !event.sessionId().isBlank(),
        "sessionId may be null (no Vaadin session id surfaced) or non-blank, but never empty");
  }

  private static void resetBootstrapWiringSingleton() throws Exception {
    var field = BootstrapWiring.class.getDeclaredField("current");
    field.setAccessible(true);
    field.set(null, null);
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static final class AllowingPolicy implements LoginAttemptPolicy {
    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) {
      return LoginAttemptDecision.allowed();
    }
    @Override public void recordSuccess(LoginAttemptContext ctx) { }
    @Override public void recordFailure(LoginAttemptContext ctx) { }
  }

  private static final class RotatingSessionPolicy implements SessionPolicy<Object> {
    private final AtomicReference<SessionContext<Object>> captured;

    RotatingSessionPolicy(AtomicReference<SessionContext<Object>> captured) {
      this.captured = captured;
    }

    @Override public SessionDecision onLogin(SessionContext<Object> context) {
      captured.set(context);
      return new SessionDecision.Invalidate("RotationAfterLogin", "/login");
    }

    @Override public SessionDecision beforeNavigation(SessionContext<Object> context) {
      return SessionDecision.Continue.INSTANCE;
    }
  }

}
