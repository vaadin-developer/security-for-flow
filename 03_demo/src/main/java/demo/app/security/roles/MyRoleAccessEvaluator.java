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
