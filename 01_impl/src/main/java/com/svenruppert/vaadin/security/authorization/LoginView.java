/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;

import java.time.LocalDateTime;


public abstract class LoginView
    extends Composite<HorizontalLayout>
    implements HasLogger {

  public static final String BTN_LOGIN_ID      = "loginview-btn-login";
  public static final String BTN_CANCEL_ID     = "loginview-btn-cancel";
  public static final String TF_USERNAME_ID    = "loginview-tf-username";
  public static final String PF_PASSWORD_ID    = "loginview-pf-password";
  public static final String CB_REMEMBER_ME_ID = "loginview-cb-remember-me";

  private final H2 title = new H2("Sign In");

  private final TextField username = new TextField("Username") {{
    setId(TF_USERNAME_ID);
    setPlaceholder("Enter your username");
    setWidthFull();
    setAutocomplete(com.vaadin.flow.component.textfield.Autocomplete.USERNAME);
  }};

  private final PasswordField password = new PasswordField("Password") {{
    setId(PF_PASSWORD_ID);
    setRequired(true);
    setPlaceholder("Enter your password");
    setWidthFull();
  }};

  private final Div customElements = new Div();

  private final Checkbox rememberMe = new Checkbox("Remember me") {{
    setId(CB_REMEMBER_ME_ID);
    setIndeterminate(false);
  }};

  private final Button btnLogin = new Button("Sign In") {{
    setId(BTN_LOGIN_ID);
    addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_LARGE);
    addClickListener(e -> validate());
    setWidthFull();
  }};

  private final Button btnCancel = new Button("Clear") {{
    setId(BTN_CANCEL_ID);
    addThemeVariants(ButtonVariant.LUMO_TERTIARY);
    addClickListener(e -> clearFields());
    setWidthFull();
  }};

  private final HorizontalLayout buttonRow = new HorizontalLayout(btnLogin, btnCancel) {{
    setWidthFull();
    setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
    expand(btnLogin);
  }};

  private final VerticalLayout card = new VerticalLayout(
      title, username, password, customElements, rememberMe, buttonRow) {{
    addClassName("login-card");
    setAlignItems(Alignment.STRETCH);
    setWidth("22em");
    setPadding(true);
    setSpacing(false);
    getThemeList().add("spacing-s");
  }};

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

  public String username() {
    return username.getValue();
  }

  public String password() {
    return password.getValue();
  }

  private void validate() {
    boolean isValid = checkCredentials();
    if (isValid) {
      logger().info("Login was accepted .. " + LocalDateTime.now());
      navigateToApp();
    } else {
      logger().warn("Login was not accepted .. " + LocalDateTime.now());
      reactOnFailedLogin();
    }
    clearFields();
  }

  public void setCustomElements(Component component) {
    customElements.add(component);
  }

  public void clearCustomElements() {
    customElements.removeAll();
  }

  public abstract void reactOnFailedLogin();

  public abstract void navigateToApp();

  public abstract boolean checkCredentials();
}
