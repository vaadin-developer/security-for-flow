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
package com.svenruppert.vaadin.security.demo.app.views;

import com.svenruppert.vaadin.security.bootstrap.CreateInitialAdminCommand;
import com.svenruppert.vaadin.security.bootstrap.InitialAdminCreationResult;
import com.svenruppert.vaadin.security.demo.app.security.bootstrap.BootstrapWiring;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;

/**
 * Initial administrator setup view.
 * <p>
 * Visible only while the system is uninitialized. After successful setup,
 * navigates to the login view; subsequent attempts to open {@code /setup}
 * are redirected to {@code /login}.
 */
@Route(SetupView.NAV)
public class SetupView extends Composite<Div> implements BeforeEnterObserver {

  public static final String NAV = "setup";

  private final PasswordField tokenField = new PasswordField("Bootstrap token");
  private final TextField usernameField = new TextField("Admin username");
  private final PasswordField passwordField = new PasswordField("New password");
  private final PasswordField confirmField = new PasswordField("Repeat password");
  private final TextField displayNameField = new TextField("Display name (optional)");
  private final TextField emailField = new TextField("Email (optional)");

  public SetupView() {
    H2 heading = new H2("Initial administrator setup");
    Paragraph hint = new Paragraph(
        "The bootstrap token is shown on the server console (transient mode) or "
            + "stored in the configured token file (persistent mode). The token "
            + "authorizes the one-time creation of the first administrator. It "
            + "is not the administrator password.");

    tokenField.setWidthFull();
    usernameField.setWidthFull();
    usernameField.setValue("admin");
    passwordField.setWidthFull();
    confirmField.setWidthFull();
    displayNameField.setWidthFull();
    emailField.setWidthFull();

    Button submit = new Button("Create administrator", e -> submit());
    submit.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

    VerticalLayout form = new VerticalLayout(
        heading, hint,
        tokenField, usernameField,
        passwordField, confirmField,
        displayNameField, emailField,
        submit);
    form.setMaxWidth("520px");
    form.addClassName("setup-view");
    getContent().add(form);
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    if (!BootstrapWiring.instance().stateService().bootstrapRequired()) {
      event.forwardTo(MyLoginView.class);
    }
  }

  private void submit() {
    String token = tokenField.getValue();
    String username = usernameField.getValue();
    String password = passwordField.getValue();
    String confirm = confirmField.getValue();
    if (token == null || token.isBlank() || username == null || username.isBlank()
        || password == null || password.isEmpty()) {
      error("Token, username and password are required.");
      return;
    }
    if (!password.equals(confirm)) {
      error("Passwords do not match.");
      return;
    }
    char[] pwd = password.toCharArray();
    InitialAdminCreationResult result = BootstrapWiring.instance().bootstrapService()
        .createInitialAdmin(new CreateInitialAdminCommand(
            token, username, pwd,
            blankToNull(displayNameField.getValue()),
            blankToNull(emailField.getValue())));
    // Drop the token reference from the form before any further UI update
    tokenField.clear();
    passwordField.clear();
    confirmField.clear();

    switch (result) {
      case InitialAdminCreationResult.Created created -> {
        success("Administrator '" + created.username() + "' created. You can now log in.");
        UI.getCurrent().navigate(MyLoginView.class);
      }
      case InitialAdminCreationResult.AlreadyInitialized ignored -> {
        info("System already initialized — redirecting to login.");
        UI.getCurrent().navigate(MyLoginView.class);
      }
      case InitialAdminCreationResult.InvalidBootstrapToken ignored -> error("Bootstrap token rejected.");
      case InitialAdminCreationResult.PasswordPolicyViolation policy ->
          error(policy.reason() == null ? "Password rejected by policy." : policy.reason());
      case InitialAdminCreationResult.InvalidUsername invalid ->
          error(invalid.reason() == null ? "Invalid username." : invalid.reason());
      case InitialAdminCreationResult.InternalError ignored ->
          error("Internal error during setup. Please retry.");
    }
  }

  private static String blankToNull(String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private static void success(String message) {
    Notification n = Notification.show(message, 3000, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_SUCCESS);
  }

  private static void info(String message) {
    Notification.show(message, 3000, Notification.Position.BOTTOM_END);
  }

  private static void error(String message) {
    Notification n = Notification.show(message, 4000, Notification.Position.BOTTOM_END);
    n.addThemeVariants(NotificationVariant.LUMO_ERROR);
  }
}
