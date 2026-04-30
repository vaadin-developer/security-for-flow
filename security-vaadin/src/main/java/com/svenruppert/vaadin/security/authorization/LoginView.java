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

import com.svenruppert.dependencies.core.logger.HasLogger;
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

import java.time.LocalDateTime;


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
      navigateToApp();
    } else {
      logger().warn("Login was not accepted .. {}", LocalDateTime.now());
      reactOnFailedLogin();
    }
    clearFields();
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
   * {@link com.svenruppert.vaadin.security.authorization.api.AuthenticationService#checkCredentials(Object)}
   * and, on success, store the subject via the configured
   * {@link com.svenruppert.vaadin.security.authorization.api.SubjectStore}.
   *
   * @return {@code true} if the credentials are valid
   */
  public abstract boolean checkCredentials();
}
