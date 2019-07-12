package demo.app.security;

import com.vaadin.flow.component.Component;
import demo.app.security.model.MyUser;
import demo.app.security.roles.VisibleFor;
import demo.app.views.MainView;
import demo.app.views.MyLoginView;
import org.jetbrains.annotations.NotNull;
import org.rapidpm.vaadin.security.authorization.LoginListener;
import org.rapidpm.vaadin.security.authorization.LoginView;

public class MyLoginListener
    extends LoginListener<MyUser> {

  public void notARestrictedTarget(Class<?> navigationTarget) {
    logger().info("NavigationTarget is not a restricted View - no login required " + navigationTarget.getSimpleName());
  }

  @NotNull
  public Class<VisibleFor> restrictionAnnotation() {
    return VisibleFor.class;
  }

  @NotNull
  public Class<? extends LoginView> loginNavigationTarget() {
    return MyLoginView.class;
  }

  @NotNull
  public Class<? extends Component> defaultNavigationTarget() {
    return MainView.class;
  }

}
