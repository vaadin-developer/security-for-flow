package demo.app.views;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.Route;
import demo.app.security.model.UserStorage.Credentials;
import demo.app.security.services.MyAuthenticationService;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.vaadin.security.authorization.LoginView;

import static demo.app.views.MyLoginView.NAV;
import static demo.app.security.model.UserStorage.userByCredentials;
import static org.rapidpm.vaadin.security.authorization.api.SessionAccessor.setCurrentSubject;

@Route(NAV)
public class MyLoginView
    extends LoginView
    implements HasLogger {

  public static final String NAV = "login";


  @Override
  public void reactOnFailedLogin() {
    logger().info("Ohhh no, Wrong Credentials.. Session close..");
    Notification.show("Credentials not accepted..");
//    VaadinSession.getCurrent().close();
//    UI.getCurrent().navigate(LoginView.class);
  }

  @Override
  public void navigateToApp() {
    //TODO r4dundant definition - see MyLoginListener
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
    final boolean permitted = new MyAuthenticationService().checkCredentials(credentials);

    if (permitted) setCurrentSubject(userByCredentials(credentials));

    return permitted;
  }
}
