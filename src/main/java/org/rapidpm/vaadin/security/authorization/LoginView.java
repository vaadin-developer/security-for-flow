package org.rapidpm.vaadin.security.authorization;

import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import org.rapidpm.dependencies.core.logger.HasLogger;

import java.time.LocalDateTime;

import static org.rapidpm.vaadin.addon.idgenerator.VaadinIDGenerator.*;


public abstract class LoginView
    extends Composite<HorizontalLayout>
    implements HasLogger {

  public static final String BTN_LOGIN_ID      = buttonID().apply(LoginView.class, "btn-login");
  public static final String BTN_CANCEL_ID     = buttonID().apply(LoginView.class, "btn-cancel");
  public static final String TF_USERNAME_ID    = textfieldID().apply(LoginView.class, "tf-username");
  public static final String PF_PASSWORD_ID    = passwordID().apply(LoginView.class, "pf-password");
  public static final String CB_REMEMBER_ME_ID = checkboxID().apply(LoginView.class, "cb-remember-me");

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
                                                           new HorizontalLayout(btnLogin, btnCancel)) {{
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

  public abstract void reactOnFailedLogin();

  public abstract void navigateToApp();

  public abstract boolean checkCredentials();
}