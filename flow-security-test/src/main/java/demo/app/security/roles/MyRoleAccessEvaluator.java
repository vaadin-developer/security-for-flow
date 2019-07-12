package demo.app.security.roles;

import com.vaadin.flow.router.Location;
import demo.app.security.model.MyUser;
import demo.app.views.MainView;
import demo.app.views.MyLoginView;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.vaadin.security.authorization.api.roles.RoleBasedAccessEvaluator;
import org.rapidpm.vaadin.security.authorization.api.roles.RoleName;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.rapidpm.vaadin.security.authorization.api.SessionAccessor.currentSubject;

public class MyRoleAccessEvaluator
    extends RoleBasedAccessEvaluator<VisibleFor, MyUser>
    implements HasLogger {

  @Override
  public Set<RoleName> requiredRoles(VisibleFor annotation) {
    return stream(annotation.value()).map(Enum::name)
                                     .map(RoleName::new)
                                     .collect(Collectors.toSet());
  }

  @Override
  public String alternativeNavigationTarget(Location location, Class<?> navigationTarget, VisibleFor annotation) {
    logger().info("alternativeNavigationTarget - " + location.getPath());
    logger().info("alternativeNavigationTarget - " + navigationTarget.getSimpleName());
    logger().info("alternativeNavigationTarget - " + Arrays.asList(annotation.value()));
    //TODO target is only on customer project known

    return (currentSubject().isPresent())
           ? MainView.NAV
           : MyLoginView.NAV;
  }

}
