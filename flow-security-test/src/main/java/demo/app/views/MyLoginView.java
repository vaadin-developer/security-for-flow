package demo.app.views;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.router.Route;
import demo.app.security.model.UserStorage.Credentials;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.vaadin.addon.idgenerator.VaadinIDGenerator;
import org.rapidpm.vaadin.security.authorization.LoginView;
import org.rapidpm.vaadin.security.authorization.api.AuthenticationService;
import org.rapidpm.vaadin.security.authorization.api.AuthenticationServiceProvider;

import static demo.app.security.model.UserStorage.userByCredentials;
import static demo.app.views.MyLoginView.NAV;
import static org.rapidpm.vaadin.security.authorization.api.SessionAccessor.setCurrentSubject;

@Route(NAV)
public class MyLoginView
    extends LoginView
    implements HasLogger {

  public static final String NAV = "login";

  public static final String DEMO_GROUPS_ID = VaadinIDGenerator.selectID()
                                                               .apply(MyLoginView.class, "demo-groups");

  //TODO demo for customizing the LoginView
  private final Select<String> select = new Select<String>() {{
    setId(DEMO_GROUPS_ID);
    setItems("Option one", "Option two");
    setPlaceholder("select group");
//    setLabel("GroupSelector");
    addValueChangeListener(event -> Notification.show("finally you made a choice.. " + event.getValue()));
  }};


  private final AuthenticationService authenticationService = new AuthenticationServiceProvider().load();


  public MyLoginView() {
    super();
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
  public boolean checkCredentials() {
    final String username = username();
    final String password = password();
    logger().info("checkCredentials - username " + username);
    logger().info("checkCredentials - password " + password);
    final Credentials credentials = new Credentials(username, password);
    final boolean permitted = authenticationService.checkCredentials(credentials);
    if (permitted) setCurrentSubject(userByCredentials(credentials));
    return permitted;
  }
}
