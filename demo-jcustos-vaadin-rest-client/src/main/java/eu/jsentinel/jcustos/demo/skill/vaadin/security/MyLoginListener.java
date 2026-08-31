package eu.jsentinel.jcustos.demo.skill.vaadin.security;

import eu.jsentinel.jcustos.authorization.LoginListener;
import eu.jsentinel.jcustos.authorization.LoginView;
import com.vaadin.flow.component.Component;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.model.User;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.DashboardView;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MyLoginView;

/**
 * Wires the framework's authentication-phase navigation listener to
 * the application's login and default route classes. Registered via
 * {@code META-INF/services/eu.jsentinel.jcustos.authorization.LoginListener}.
 */
public class MyLoginListener extends LoginListener<User> {

  @Override
  public void notARestrictedTarget(Class<?> navigationTarget) {
    logger().info("Unrestricted navigation target — no login required: {}",
        navigationTarget.getSimpleName());
  }

  @Override
  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }

  @Override
  public Class<? extends Component> defaultNavigationTarget() {
    return DashboardView.class;
  }
}
