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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.audit.SessionInvalidated;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectIdResolver;
import com.svenruppert.jsentinel.authorization.api.SubjectStore;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.session.JSentinelVersion;
import com.svenruppert.jsentinel.session.JSentinelVersionKey;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;
import com.svenruppert.jsentinel.session.SessionContext;
import com.svenruppert.jsentinel.session.SessionDecision;
import com.svenruppert.jsentinel.session.SessionPolicy;
import com.svenruppert.jsentinel.session.vaadin.VaadinJSentinelVersionContext;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.Autocomplete;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinSession;
import com.vaadin.flow.server.WrappedSession;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;


/**
 * Abstract base class for login views.
 * <p>
 * Provides a pre-built login form with username, password, remember-me
 * checkbox, and sign-in / clear buttons. Subclasses implement the three
 * abstract methods to wire credential checking, navigation after login,
 * and error handling.
 * <p>
 * The form can be extended with custom UI elements via
 * {@link #setCustomElements(Component)}.
 */
public abstract class LoginView
    extends Composite<HorizontalLayout>
    implements HasLogger {

  /** Test ID for the login button. */
  public static final String BTN_LOGIN_ID      = "loginview-btn-login";
  /** Test ID for the cancel/clear button. */
  public static final String BTN_CANCEL_ID     = "loginview-btn-cancel";
  /** Test ID for the username field. */
  public static final String TF_USERNAME_ID    = "loginview-tf-username";
  /** Test ID for the password field. */
  public static final String PF_PASSWORD_ID    = "loginview-pf-password";
  /** Test ID for the remember-me checkbox. */
  public static final String CB_REMEMBER_ME_ID = "loginview-cb-remember-me";

  /** Form title heading. */
  private final H2 title = new H2("Sign In");

  /** Username input field. */
  private final TextField username = new TextField("Username") {{
    setId(TF_USERNAME_ID);
    setPlaceholder("Enter your username");
    setWidthFull();
    setAutocomplete(Autocomplete.USERNAME);
  }};

  /** Password input field. */
  private final PasswordField password = new PasswordField("Password") {{
    setId(PF_PASSWORD_ID);
    setRequired(true);
    setPlaceholder("Enter your password");
    setWidthFull();
  }};

  /** Container for custom elements added via {@link #setCustomElements(Component)}. */
  private final Div customElements = new Div();

  /** Remember-me checkbox. */
  private final Checkbox rememberMe = new Checkbox("Remember me") {{
    setId(CB_REMEMBER_ME_ID);
    setIndeterminate(false);
  }};

  /** Sign-in button that triggers credential validation. */
  private final Button btnLogin = new Button("Sign In") {{
    setId(BTN_LOGIN_ID);
    addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_LARGE);
    addClickListener(e -> validate());
    setWidthFull();
  }};

  /** Clear button that resets the form fields. */
  private final Button btnCancel = new Button("Clear") {{
    setId(BTN_CANCEL_ID);
    addThemeVariants(ButtonVariant.LUMO_TERTIARY);
    addClickListener(e -> clearFields());
    setWidthFull();
  }};

  /** Row containing the login and cancel buttons. */
  private final HorizontalLayout buttonRow = new HorizontalLayout(btnLogin, btnCancel) {{
    setWidthFull();
    setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
    expand(btnLogin);
  }};

  /** Card layout containing all form elements. */
  private final VerticalLayout card = new VerticalLayout(
      title, username, password, customElements, rememberMe, buttonRow) {{
    addClassName("login-card");
    setAlignItems(Alignment.STRETCH);
    setWidth("22em");
    setPadding(true);
    setSpacing(false);
    getThemeList().add("spacing-s");
  }};

  /**
   * Assembles the login form layout.
   */
  public LoginView() {
    logger().info("setting now the login ui content..");
    final HorizontalLayout wrapper = getContent();
    wrapper.addClassName("login-view");
    wrapper.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
    wrapper.setJustifyContentMode(FlexComponent.JustifyContentMode.CENTER);
    wrapper.add(card);
    wrapper.setSizeFull();
  }

  private void clearFields() {
    username.clear();
    password.clear();
  }

  /**
   * Returns the current value of the username field.
   *
   * @return the entered username
   */
  public String username() {
    return username.getValue();
  }

  /**
   * Returns the current value of the password field.
   *
   * @return the entered password
   */
  public String password() {
    return password.getValue();
  }

  private void validate() {
    boolean isValid = checkCredentials();
    if (isValid) {
      logger().info("Login was accepted .. {}", LocalDateTime.now());
      notifyOnLogin();
      captureJSentinelVersionSnapshot();
      navigateToApp();
    } else {
      logger().warn("Login was not accepted .. {}", LocalDateTime.now());
      reactOnFailedLogin();
    }
    clearFields();
  }

  /**
   * Phase 4c-Followup: best-effort capture of the
   * {@link JSentinelVersion} snapshot into
   * {@link VaadinJSentinelVersionContext} so the
   * {@code JSentinelVersionEnforcerListener} can detect drift on
   * subsequent requests.
   * <p>
   * Fires after {@link #notifyOnLogin()} so any session rotation
   * has already happened and the recorded {@code sessionId}
   * matches the new servlet session. The capture is a strict
   * three-way no-op when any prerequisite is missing:
   * <ol>
   *   <li>No SPI-registered {@link JSentinelVersionStore} (Phase 4a
   *       not wired) — skip.</li>
   *   <li>No SPI-registered {@link SubjectIdResolver} — the
   *       framework cannot derive a {@link SubjectId} from the
   *       application's typed user, so skip.</li>
   *   <li>No active Vaadin session / no current subject — skip.</li>
   * </ol>
   * Any exception thrown by the resolver, the store, or
   * {@link VaadinJSentinelVersionContext#record} is swallowed —
   * snapshot capture must never block the login flow.
   */
  @SuppressWarnings({"unchecked", "rawtypes"})
  private void captureJSentinelVersionSnapshot() {
    try {
      Optional<JSentinelVersionStore> storeOpt = JSentinelServiceResolver.findJSentinelVersionStore();
      if (storeOpt.isEmpty()) {
        return;
      }
      Optional<SubjectIdResolver<Object>> resolverOpt =
          JSentinelServiceResolver.findSubjectIdResolver();
      if (resolverOpt.isEmpty()) {
        return;
      }
      Object subject = currentSubject().orElse(null);
      if (subject == null) {
        return;
      }
      VaadinSession session = VaadinSession.getCurrent();
      if (session == null) {
        return;
      }
      SubjectIdResolver<Object> resolver = resolverOpt.get();
      SubjectId subjectId = resolver.resolve(subject);
      TenantId tenant = resolver.tenantFor(subject);
      JSentinelVersion snapshot = storeOpt.get()
          .current(new JSentinelVersionKey(tenant, subjectId));
      WrappedSession wrapped = session.getSession();
      String sessionId = wrapped == null ? null : wrapped.getId();
      VaadinJSentinelVersionContext.record(session, subjectId, tenant, snapshot, sessionId);
    } catch (RuntimeException captureFailure) {
      logger().warn("JSentinelVersion snapshot capture failed: {}", captureFailure.toString());
    }
  }

  /**
   * Best-effort notification of {@link SessionPolicy#onLogin(SessionContext)}.
   * <p>
   * Fires after a successful {@link #checkCredentials()} so the policy can
   * emit a {@code SessionCreated} audit event and, when configured, trigger
   * session-id rotation. Failures, missing Vaadin session, or missing SPI
   * are silently absorbed — the lifecycle hook must never block the login
   * flow.
   * <p>
   * If the policy returns
   * {@link SessionDecision.Invalidate Invalidate} the listener
   * reinitializes the HTTP session via
   * {@link VaadinService#reinitializeSession(VaadinRequest)} (session-id
   * rotates, VaadinSession attributes — including the just-bound subject —
   * survive) and emits a {@code SessionInvalidated} audit event for the
   * <em>old</em> session id. The {@code loginRoute} field of the decision
   * is deliberately ignored in the post-login context: the user proceeds
   * to {@link #navigateToApp()} on the rotated session. Invalidation
   * <em>from {@code beforeNavigation}</em> (session expired) follows a
   * different code path and uses {@code loginRoute} as written.
   */
  private void notifyOnLogin() {
    try {
      SessionPolicy<Object> policy = JSentinelServiceResolver.sessionPolicy();
      Optional<SessionContext<Object>> contextOpt = buildSessionContext();
      if (contextOpt.isEmpty()) {
        return;
      }
      SessionContext<Object> context = contextOpt.get();
      SessionDecision decision = policy.onLogin(context);
      if (decision instanceof SessionDecision.Invalidate invalidate) {
        rotateSessionAfterLogin(context, invalidate);
      }
    } catch (RuntimeException notifyFailure) {
      logger().warn("SessionPolicy.onLogin notification failed: {}", notifyFailure.toString());
    }
  }

  /**
   * Rotates the underlying HTTP session id while preserving the
   * {@link VaadinSession} (and therefore the just-bound subject). Standard
   * session-fixation mitigation: callers that pass credentials over a
   * pre-existing session id cannot replay the post-login session because
   * the id changes here.
   * <p>
   * Audit emit is best-effort and never propagates exceptions.
   */
  private void rotateSessionAfterLogin(SessionContext<Object> context, SessionDecision.Invalidate decision) {
    VaadinRequest request = VaadinRequest.getCurrent();
    if (request == null) {
      return;
    }
    String oldSessionId = context.sessionId();
    try {
      VaadinService.reinitializeSession(request);
    } catch (RuntimeException rotationFailure) {
      logger().warn("VaadinService.reinitializeSession failed: {}",
          rotationFailure.toString());
      return;
    }
    auditRotation(context, oldSessionId, decision.reason());
  }

  private void auditRotation(SessionContext<Object> context, String oldSessionId, String reason) {
    try {
      JSentinelAuditService sink = JSentinelServiceResolver.securityAuditService();
      sink.publish(new SessionInvalidated(
          Instant.now(),
          subjectIdOf(context),
          oldSessionId,
          reason == null ? "RotationAfterLogin" : reason));
    } catch (RuntimeException auditFailure) {
      // never block login because the audit sink failed
    }
  }

  private static String subjectIdOf(SessionContext<Object> context) {
    Object subject = context.subject();
    return subject == null ? "" : subject.toString();
  }

  /**
   * Builds a {@link SessionContext} from the current Vaadin runtime —
   * subject (best-effort, looked up via the active
   * {@link SubjectStore} keyed on the application's subject type),
   * sessionId + createdAt from the {@link WrappedSession}, lastActivity
   * = createdAt for a fresh login, clientAddress from the
   * {@link VaadinRequest}.
   *
   * @return populated context, or empty when no Vaadin session is bound
   */
  private static Optional<SessionContext<Object>> buildSessionContext() {
    VaadinSession vaadin = VaadinSession.getCurrent();
    if (vaadin == null) {
      return Optional.empty();
    }
    WrappedSession wrapped = vaadin.getSession();
    Instant createdAt = wrapped == null
        ? Instant.now()
        : Instant.ofEpochMilli(wrapped.getCreationTime());
    String sessionId = wrapped == null ? null : wrapped.getId();
    String clientAddress = currentClientAddress();
    Object subject = currentSubject().orElse(null);
    return Optional.of(new SessionContext<>(
        subject, sessionId, createdAt, createdAt, clientAddress, Map.of()));
  }

  private static Optional<Object> currentSubject() {
    try {
      Class<?> subjectType = JSentinelServiceResolver
          .<Object, Object>authenticationService()
          .subjectType();
      if (subjectType == null) {
        return Optional.empty();
      }
      SubjectStore store = SubjectStores.findSubjectStore().orElse(null);
      if (store == null) {
        return Optional.empty();
      }
      @SuppressWarnings({"rawtypes", "unchecked"})
      Class raw = subjectType;
      return store.currentSubject(raw).map(value -> (Object) value);
    } catch (RuntimeException ignored) {
      return Optional.empty();
    }
  }

  private static String currentClientAddress() {
    try {
      VaadinRequest request = VaadinRequest.getCurrent();
      return request == null ? null : request.getRemoteAddr();
    } catch (RuntimeException ignored) {
      return null;
    }
  }

  /**
   * Adds a custom UI component to the login form (below the password
   * field and above the remember-me checkbox).
   *
   * @param component the component to add
   */
  public void setCustomElements(Component component) {
    customElements.add(component);
  }

  /**
   * Removes all previously added custom elements from the login form.
   */
  public void clearCustomElements() {
    customElements.removeAll();
  }

  /**
   * Called when credential validation fails.
   * Implementations typically show a notification or close the session.
   */
  public abstract void reactOnFailedLogin();

  /**
   * Called after successful credential validation.
   * Implementations typically navigate to the main application view.
   */
  public abstract void navigateToApp();

  /**
   * Validates the credentials entered by the user.
   * Implementations should call
   * {@link com.svenruppert.jsentinel.authentication.AuthenticationService#checkCredentials(Object)}
   * and, on success, store the subject via the configured
   * {@link com.svenruppert.jsentinel.authorization.api.SubjectStore}.
   *
   * @return {@code true} if the credentials are valid
   */
  public abstract boolean checkCredentials();
}
