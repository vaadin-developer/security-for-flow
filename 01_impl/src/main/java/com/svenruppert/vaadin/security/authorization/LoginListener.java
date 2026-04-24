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
package com.svenruppert.vaadin.security.authorization;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.authorization.api.SessionAccessor;
import com.svenruppert.vaadin.security.authorization.navigation.NavigationAccessDecision;
import com.svenruppert.vaadin.security.authorization.navigation.NavigationAccessDecisionService;
import com.svenruppert.vaadin.security.authorization.navigation.NavigationSecurityContext;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;
import java.lang.annotation.Annotation;


/**
 * The final implementation inside a project must be "activated" with its FQN
 * in a file META-INF/services/com.svenruppert.vaadin.security.authorization.LoginListener.
 * <p>
 * Delegates authentication-phase navigation decisions to
 * {@link NavigationAccessDecisionService}, keeping this class as a thin
 * Vaadin adapter.
 *
 * @param <U> the type that is used for the subject in the current project. It is the same as
 *            the result type of the method - public Class U  subjectType();
 */
public abstract class LoginListener<U>
    implements BeforeEnterListener, HasLogger {

  private final NavigationAccessDecisionService decisionService = new NavigationAccessDecisionService();

  @Override
  public void beforeEnter(BeforeEnterEvent beforeEnterEvent) {
    final Class<?> navigationTarget = beforeEnterEvent.getNavigationTarget();
    final boolean isRestricted = navigationTarget.isAnnotationPresent(restrictionAnnotation());
    final boolean isLoginView = navigationTarget.equals(loginNavigationTarget());
    final boolean subjectAvailable = SessionAccessor.<U>currentSubject().isPresent();

    NavigationSecurityContext ctx = new NavigationSecurityContext(
        navigationTarget, isRestricted, subjectAvailable, isLoginView);

    NavigationAccessDecision decision = decisionService.evaluateAuthentication(ctx);

    applyDecision(decision, beforeEnterEvent, navigationTarget);
  }

  private void applyDecision(NavigationAccessDecision decision,
                             BeforeEnterEvent event,
                             Class<?> navigationTarget) {
    switch (decision) {
      case NavigationAccessDecision.Allowed() -> {
        if (!navigationTarget.isAnnotationPresent(restrictionAnnotation())) {
          notARestrictedTarget(navigationTarget);
        } else {
          logger().info("User is already logged in");
        }
      }
      case NavigationAccessDecision.LoginRequired() -> {
        logger().info("Login required — forwarding to login view");
        event.forwardTo(loginNavigationTarget());
      }
      case NavigationAccessDecision.AlreadyLoggedIn() -> {
        logger().info("Already logged in — forwarding to default view");
        event.forwardTo(defaultNavigationTarget());
      }
      case NavigationAccessDecision.AccessDenied(String route, boolean asForward) -> {
        if (asForward) event.forwardTo(route);
        else event.rerouteTo(route);
      }
    }
  }

  public abstract void notARestrictedTarget(Class<?> navigationTarget);

  /**
   * This is the Annotation - Type that is used for the restriction declaration on class-level.
   * For Example VisibleFor.class
   *
   * @return the restriction Annotation class for the current project
   */
  public abstract Class<? extends Annotation> restrictionAnnotation();

  /**
   * The LoginView that should be used.
   *
   * @return the class with the Route Annotation for the login view
   */
  public abstract Class<? extends LoginView> loginNavigationTarget();


  /**
   * The class with the Route Annotation that will point to the default view in the current project.
   * Mostly this is the view that should be used after a login.
   *
   * @return the class with the Route Annotation for the default (main) view
   */
  public abstract Class<? extends Component> defaultNavigationTarget();
}
