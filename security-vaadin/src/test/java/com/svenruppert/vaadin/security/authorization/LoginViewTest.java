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
package com.svenruppert.vaadin.security.authorization;

import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.Autocomplete;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoginView")
class LoginViewTest {

  @Test
  @DisplayName("constructor builds a login-view wrapper layout containing the card")
  void constructionAssemblesUiTree() {
    TestLoginView view = new TestLoginView();

    HorizontalLayout wrapper = view.getContent();
    assertNotNull(wrapper);
    assertTrue(wrapper.getClassNames().contains("login-view"),
        "wrapper must carry the 'login-view' CSS class");
    assertEquals(1L, wrapper.getChildren().count(),
        "wrapper must contain exactly the card layout");
  }

  @Test
  @DisplayName("test ID constants are stable identifiers")
  void testIdsAreStable() {
    assertEquals("loginview-tf-username", LoginView.TF_USERNAME_ID);
    assertEquals("loginview-pf-password", LoginView.PF_PASSWORD_ID);
    assertEquals("loginview-btn-login",   LoginView.BTN_LOGIN_ID);
    assertEquals("loginview-btn-cancel",  LoginView.BTN_CANCEL_ID);
    assertEquals("loginview-cb-remember-me", LoginView.CB_REMEMBER_ME_ID);
  }

  @Test
  @DisplayName("username() / password() read the current field values")
  void usernameAndPasswordReadValues() throws Exception {
    TestLoginView view = new TestLoginView();
    field(view, "username", TextField.class).setValue("alice");
    field(view, "password", PasswordField.class).setValue("s3cret");

    assertEquals("alice",  view.username());
    assertEquals("s3cret", view.password());
  }

  @Test
  @DisplayName("setCustomElements adds a component to the custom-elements container")
  void setCustomElementsAdds() throws Exception {
    TestLoginView view = new TestLoginView();
    Div container = field(view, "customElements", Div.class);
    Span hint = new Span("hint");

    view.setCustomElements(hint);

    assertEquals(1L, container.getChildren().count());
    assertSame(hint, container.getChildren().findFirst().orElseThrow());
  }

  @Test
  @DisplayName("clearCustomElements removes every previously added component")
  void clearCustomElementsRemovesAll() throws Exception {
    TestLoginView view = new TestLoginView();
    view.setCustomElements(new Span("a"));
    view.setCustomElements(new Span("b"));
    Div container = field(view, "customElements", Div.class);

    view.clearCustomElements();

    assertEquals(0L, container.getChildren().count());
  }

  @Test
  @DisplayName("validate() calls navigateToApp() and clears fields when credentials are valid")
  void validateAcceptsCredentials() throws Exception {
    TestLoginView view = new TestLoginView();
    view.acceptCredentials = true;
    field(view, "username", TextField.class).setValue("u");
    field(view, "password", PasswordField.class).setValue("p");

    invokeValidate(view);

    assertTrue(view.navigatedToApp,
        "navigateToApp must be called when checkCredentials returns true");
    assertFalse(view.reactedOnFailedLogin);
    assertEquals("", view.username(),
        "username field must be cleared after a successful validation");
    assertEquals("", view.password(),
        "password field must be cleared after a successful validation");
  }

  @Test
  @DisplayName("validate() calls reactOnFailedLogin() and clears fields when credentials are invalid")
  void validateRejectsCredentials() throws Exception {
    TestLoginView view = new TestLoginView();
    view.acceptCredentials = false;
    field(view, "username", TextField.class).setValue("u");
    field(view, "password", PasswordField.class).setValue("p");

    invokeValidate(view);

    assertTrue(view.reactedOnFailedLogin,
        "reactOnFailedLogin must be called when checkCredentials returns false");
    assertFalse(view.navigatedToApp);
    assertEquals("", view.username());
    assertEquals("", view.password());
  }

  @Test
  @DisplayName("validate() success notifies SessionPolicy.onLogin (no-op when no Vaadin session is bound)")
  void validateSuccessIsAuditSilentWithoutVaadinSession() throws Exception {
    com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.resetAll();
    RecordingSessionPolicy<String> policy = new RecordingSessionPolicy<>();
    com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.setSessionPolicy(policy);

    try {
      TestLoginView view = new TestLoginView();
      view.acceptCredentials = true;
      field(view, "username", TextField.class).setValue("u");
      field(view, "password", PasswordField.class).setValue("p");

      invokeValidate(view);

      // No VaadinSession is bound in unit-test context, so the policy is
      // not notified. The login still succeeds — the lifecycle hook is
      // best-effort and silently degrades.
      assertTrue(view.navigatedToApp);
      assertEquals(0, policy.onLoginCalls,
          "without an active VaadinSession the policy must not be invoked");
    } finally {
      com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.resetAll();
    }
  }

  @Test
  @DisplayName("validate() failure does NOT notify SessionPolicy.onLogin")
  void validateFailureSkipsSessionPolicy() throws Exception {
    com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.resetAll();
    RecordingSessionPolicy<String> policy = new RecordingSessionPolicy<>();
    com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.setSessionPolicy(policy);

    try {
      TestLoginView view = new TestLoginView();
      view.acceptCredentials = false;
      field(view, "username", TextField.class).setValue("u");
      field(view, "password", PasswordField.class).setValue("p");

      invokeValidate(view);

      assertEquals(0, policy.onLoginCalls,
          "policy.onLogin must only fire on a successful credential check");
    } finally {
      com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.resetAll();
    }
  }

  @Test
  @DisplayName("validate() success absorbs an Invalidate decision from onLogin without throwing")
  void invalidateFromOnLoginIsAbsorbed() throws Exception {
    com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.resetAll();
    InvalidatingSessionPolicy<String> policy = new InvalidatingSessionPolicy<>();
    com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.setSessionPolicy(policy);

    try {
      TestLoginView view = new TestLoginView();
      view.acceptCredentials = true;
      field(view, "username", TextField.class).setValue("u");
      field(view, "password", PasswordField.class).setValue("p");

      // The honour path needs an active VaadinRequest to call
      // VaadinService.reinitializeSession(...); none is bound here.
      // The view must still complete the login flow cleanly — the
      // rotation is a best-effort side effect.
      invokeValidate(view);

      assertTrue(view.navigatedToApp,
          "even when onLogin asks for rotation, navigateToApp must run");
    } finally {
      com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver.resetAll();
    }
  }

  static final class RecordingSessionPolicy<U>
      implements com.svenruppert.vaadin.security.session.SessionPolicy<U> {
    int onLoginCalls;

    @Override
    public com.svenruppert.vaadin.security.session.SessionDecision onLogin(
        com.svenruppert.vaadin.security.session.SessionContext<U> context) {
      onLoginCalls++;
      return com.svenruppert.vaadin.security.session.SessionDecision.Continue.INSTANCE;
    }

    @Override
    public com.svenruppert.vaadin.security.session.SessionDecision beforeNavigation(
        com.svenruppert.vaadin.security.session.SessionContext<U> context) {
      return com.svenruppert.vaadin.security.session.SessionDecision.Continue.INSTANCE;
    }
  }

  static final class InvalidatingSessionPolicy<U>
      implements com.svenruppert.vaadin.security.session.SessionPolicy<U> {

    @Override
    public com.svenruppert.vaadin.security.session.SessionDecision onLogin(
        com.svenruppert.vaadin.security.session.SessionContext<U> context) {
      return new com.svenruppert.vaadin.security.session.SessionDecision.Invalidate(
          "RotationAfterLogin", "/login");
    }

    @Override
    public com.svenruppert.vaadin.security.session.SessionDecision beforeNavigation(
        com.svenruppert.vaadin.security.session.SessionContext<U> context) {
      return com.svenruppert.vaadin.security.session.SessionDecision.Continue.INSTANCE;
    }
  }

  // ── Field configuration ──────────────────────────────────────

  @Test
  @DisplayName("username field is configured with id, placeholder, full width and autocomplete")
  void usernameFieldConfigured() throws Exception {
    TestLoginView view = new TestLoginView();
    TextField field = field(view, "username", TextField.class);

    assertEquals(LoginView.TF_USERNAME_ID, field.getId().orElseThrow());
    assertEquals("Enter your username", field.getPlaceholder());
    assertEquals("100%", field.getWidth());
    assertEquals(Autocomplete.USERNAME, field.getAutocomplete());
  }

  @Test
  @DisplayName("password field is configured with id, required, placeholder and full width")
  void passwordFieldConfigured() throws Exception {
    TestLoginView view = new TestLoginView();
    PasswordField field = field(view, "password", PasswordField.class);

    assertEquals(LoginView.PF_PASSWORD_ID, field.getId().orElseThrow());
    assertTrue(field.isRequired(), "password field must be required");
    assertEquals("Enter your password", field.getPlaceholder());
    assertEquals("100%", field.getWidth());
  }

  @Test
  @DisplayName("remember-me checkbox is configured with id and starts non-indeterminate")
  void rememberMeConfigured() throws Exception {
    TestLoginView view = new TestLoginView();
    Checkbox checkbox = field(view, "rememberMe", Checkbox.class);

    assertEquals(LoginView.CB_REMEMBER_ME_ID, checkbox.getId().orElseThrow());
    assertFalse(checkbox.isIndeterminate());
  }

  @Test
  @DisplayName("login button has the expected id, label and full width")
  void loginButtonConfigured() throws Exception {
    TestLoginView view = new TestLoginView();
    Button btn = field(view, "btnLogin", Button.class);

    assertEquals(LoginView.BTN_LOGIN_ID, btn.getId().orElseThrow());
    assertEquals("Sign In", btn.getText());
    assertEquals("100%", btn.getWidth());
  }

  @Test
  @DisplayName("cancel button has the expected id, label and full width")
  void cancelButtonConfigured() throws Exception {
    TestLoginView view = new TestLoginView();
    Button btn = field(view, "btnCancel", Button.class);

    assertEquals(LoginView.BTN_CANCEL_ID, btn.getId().orElseThrow());
    assertEquals("Clear", btn.getText());
    assertEquals("100%", btn.getWidth());
  }

  @Test
  @DisplayName("button row layout uses full width and centered vertical alignment")
  void buttonRowConfigured() throws Exception {
    TestLoginView view = new TestLoginView();
    HorizontalLayout row = field(view, "buttonRow", HorizontalLayout.class);

    assertEquals("100%", row.getWidth());
    assertEquals(FlexComponent.Alignment.CENTER, row.getDefaultVerticalComponentAlignment());
  }

  @Test
  @DisplayName("card layout has login-card class, fixed width, padding, and stretch alignment")
  void cardConfigured() throws Exception {
    TestLoginView view = new TestLoginView();
    VerticalLayout card = field(view, "card", VerticalLayout.class);

    assertTrue(card.getClassNames().contains("login-card"),
        "card must carry the 'login-card' CSS class");
    assertEquals("22em", card.getWidth());
    assertTrue(card.isPadding());
    assertEquals(VerticalLayout.Alignment.STRETCH, card.getAlignItems());
  }

  @Test
  @DisplayName("wrapper layout (Composite content) is centered both vertically and horizontally and full-size")
  void wrapperConfigured() {
    TestLoginView view = new TestLoginView();
    HorizontalLayout wrapper = view.getContent();

    assertEquals(FlexComponent.Alignment.CENTER, wrapper.getDefaultVerticalComponentAlignment());
    assertEquals(FlexComponent.JustifyContentMode.CENTER, wrapper.getJustifyContentMode());
    assertEquals("100%", wrapper.getWidth());
    assertEquals("100%", wrapper.getHeight());
  }

  @Test
  @DisplayName("clicking the cancel button clears username and password")
  void cancelButtonClearsFields() throws Exception {
    TestLoginView view = new TestLoginView();
    field(view, "username", TextField.class).setValue("u");
    field(view, "password", PasswordField.class).setValue("p");
    Button cancel = field(view, "btnCancel", Button.class);

    cancel.click();

    assertEquals("", view.username());
    assertEquals("", view.password());
  }

  @Test
  @DisplayName("clicking the login button triggers validate() and reaches the failure branch")
  void loginButtonTriggersValidate() throws Exception {
    TestLoginView view = new TestLoginView();
    view.acceptCredentials = false;
    Button login = field(view, "btnLogin", Button.class);

    login.click();

    assertTrue(view.reactedOnFailedLogin,
        "the login button click listener must invoke validate() which calls reactOnFailedLogin");
  }

  @Test
  @DisplayName("login button advertises Lumo primary + large theme variants")
  void loginButtonThemeVariants() throws Exception {
    TestLoginView view = new TestLoginView();
    Button btn = field(view, "btnLogin", Button.class);

    assertTrue(btn.getThemeNames().contains("primary"),
        "login button must carry the lumo primary theme variant");
    assertTrue(btn.getThemeNames().contains("large"),
        "login button must carry the lumo large theme variant");
  }

  @Test
  @DisplayName("cancel button advertises Lumo tertiary theme variant")
  void cancelButtonThemeVariant() throws Exception {
    TestLoginView view = new TestLoginView();
    Button btn = field(view, "btnCancel", Button.class);

    assertTrue(btn.getThemeNames().contains("tertiary"),
        "cancel button must carry the lumo tertiary theme variant");
  }

  @Test
  @DisplayName("button row expands the login button to fill available space")
  void buttonRowExpandsLogin() throws Exception {
    TestLoginView view = new TestLoginView();
    Button btnLogin = field(view, "btnLogin", Button.class);

    String flexGrow = btnLogin.getElement().getStyle().get("flexGrow");
    assertNotNull(flexGrow, "expand(btnLogin) must set a flexGrow style on the button");
    assertEquals("1.0", flexGrow,
        "expand(component) sets flexGrow:1 on the expanded component");
  }

  @Test
  @DisplayName("card layout uses spacing-s theme override (spacing(false) + spacing-s theme)")
  void cardSpacingTheme() throws Exception {
    TestLoginView view = new TestLoginView();
    VerticalLayout card = field(view, "card", VerticalLayout.class);

    assertFalse(card.isSpacing(),
        "card constructor calls setSpacing(false)");
    assertTrue(card.getThemeNames().contains("spacing-s"),
        "card carries the 'spacing-s' theme override");
  }

  // ── Reflection helpers ────────────────────────────────────────

  private static <T> T field(LoginView view, String name, Class<T> type) throws Exception {
    Field f = LoginView.class.getDeclaredField(name);
    f.setAccessible(true);
    return type.cast(f.get(view));
  }

  private static void invokeValidate(LoginView view) throws Exception {
    Method m = LoginView.class.getDeclaredMethod("validate");
    m.setAccessible(true);
    m.invoke(view);
  }

  // ── Test fixture ──────────────────────────────────────────────

  static final class TestLoginView extends LoginView {

    boolean acceptCredentials;
    boolean navigatedToApp;
    boolean reactedOnFailedLogin;

    @Override public boolean checkCredentials() { return acceptCredentials; }

    @Override public void navigateToApp() { navigatedToApp = true; }

    @Override public void reactOnFailedLogin() { reactedOnFailedLogin = true; }
  }
}
