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
package org.rapidpm.vaadin.security.authorization;

import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.rapidpm.dependencies.core.logger.HasLogger;

import java.time.LocalDateTime;


public abstract class LoginView
    extends Composite<HorizontalLayout>
    implements HasLogger {

  public static final String BTN_LOGIN_ID      = "loginview-btn-login";
  public static final String BTN_CANCEL_ID     = "loginview-btn-cancel";
  public static final String TF_USERNAME_ID    = "loginview-tf-username";
  public static final String PF_PASSWORD_ID    = "loginview-pf-password";
  public static final String CB_REMEMBER_ME_ID = "loginview-cb-remember-me";

  private final TextField username = new TextField() {{
    setId(TF_USERNAME_ID);
    setPlaceholder("username");
  }};

  private final PasswordField password = new PasswordField() {{
    setId(PF_PASSWORD_ID);
    setRequired(true);
    setPlaceholder("password");
  }};

  private final Checkbox rememberMe = new Checkbox() {{
    setId(CB_REMEMBER_ME_ID);
    setLabel("remember me");
    setIndeterminate(false);
  }};

  private final Div customElements = new Div() {{
    //TODO defaults ??
  }};


  private final Button btnLogin = new Button() {{
    setId(BTN_LOGIN_ID);
    setText("Login");
    addClickListener(e -> validate());
  }};

  private final Button btnCancel = new Button() {{
    setId(BTN_CANCEL_ID);
    setText("Cancel");
    addClickListener(e -> clearFields());
  }};

  private final VerticalLayout layout = new VerticalLayout(new HorizontalLayout(username, password), rememberMe,
                                                           customElements, new HorizontalLayout(btnLogin, btnCancel)) {{
    setDefaultHorizontalComponentAlignment(Alignment.START);
    setSizeUndefined();
  }};

  public LoginView() {
    logger().info("setting now the login ui content..");
    final HorizontalLayout wrappedLayout = getContent();
    wrappedLayout.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
    wrappedLayout.setJustifyContentMode(FlexComponent.JustifyContentMode.CENTER);
    wrappedLayout.add(layout);
    wrappedLayout.setSizeFull();
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
      logger().warning("Login was not accepted .. " + LocalDateTime.now());
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