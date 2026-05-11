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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.demo.app.security.bootstrap.BootstrapWiring;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.Route;
import com.svenruppert.vaadin.security.demo.app.security.model.Credentials;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.authorization.LoginView;
import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;

import static com.svenruppert.vaadin.security.demo.app.views.MyLoginView.NAV;

@Route(NAV)
public class MyLoginView
    extends LoginView
    implements HasLogger, BeforeEnterObserver {

  public static final String NAV = "login";

  public static final String DEMO_GROUPS_ID = "my-login-view-demo-groups";

  //TODO demo for customizing the LoginView
  private final Select<String> select = new Select<>() {{
    setId(DEMO_GROUPS_ID);
    setItems("Option one", "Option two");
    setPlaceholder("select group");
//    setLabel("GroupSelector");
    addValueChangeListener(event -> Notification.show("finally you made a choice.. " + event.getValue()));
  }};


  private final AuthenticationService<Credentials, MyUser> authenticationService
      = SecurityServiceResolver.authenticationService();

  public MyLoginView() {
    super();
    //adding custom element to LoginView
    setCustomElements(select);
  }

  @Override
  public void reactOnFailedLogin() {
    logger().info("Ohhh no, Wrong Credentials.. Session close..");
    Notification.show("Credentials not accepted..");
//    VaadinSession.getCurrent().close();
//    UI.getCurrent().navigate(LoginView.class);
  }

  @Override
  public void navigateToApp() {
    //TODO redundant definition - see MyLoginListener
    UI.getCurrent()
      .navigate(MainView.class);
  }

  @Override
  public void beforeEnter(BeforeEnterEvent event) {
    if (BootstrapWiring.instance().stateService().bootstrapRequired()) {
      event.forwardTo(SetupView.class);
    }
  }

  @Override
  public boolean checkCredentials() {
    final String username = username();
    final String password = password();
    logger().info("checkCredentials - username {}", username);
    final Credentials credentials = new Credentials(username, password);
    final boolean permitted = authenticationService.checkCredentials(credentials);
    if (permitted) {
      DemoUserDirectoryProvider.directory().findByCredentials(credentials)
          .ifPresent(user -> SubjectStores.subjectStore().setCurrentSubject(user, MyUser.class));
    }
    return permitted;
  }
}
