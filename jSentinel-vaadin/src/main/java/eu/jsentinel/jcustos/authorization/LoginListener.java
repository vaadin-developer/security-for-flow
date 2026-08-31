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
package eu.jsentinel.jcustos.authorization;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.impl.JSentinelAnnotationScanner;
import eu.jsentinel.jcustos.authorization.impl.VaadinNavigationAccessDecisionMapper;
import eu.jsentinel.jcustos.authorization.navigation.NavigationAccessDecision;
import eu.jsentinel.jcustos.authorization.navigation.NavigationAccessDecisionService;
import eu.jsentinel.jcustos.authorization.navigation.NavigationJSentinelContext;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterListener;


/**
 * The final implementation inside a project must be "activated" with its FQN
 * in a file META-INF/services/eu.jsentinel.jcustos.authorization.LoginListener.
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

  /** Decision service for authentication-phase navigation checks. */
  private final NavigationAccessDecisionService decisionService = new NavigationAccessDecisionService();

  /** Scanner for framework security annotations. */
  private final JSentinelAnnotationScanner scanner = new JSentinelAnnotationScanner();

  /** Maps authentication-phase decisions to Vaadin navigation operations. */
  private final VaadinNavigationAccessDecisionMapper decisionMapper =
      new VaadinNavigationAccessDecisionMapper();

  /** Creates a new login listener. */
  protected LoginListener() {
  }

  @Override
  public void beforeEnter(BeforeEnterEvent beforeEnterEvent) {
    final Class<?> navigationTarget = beforeEnterEvent.getNavigationTarget();
    final boolean isRestricted = isRestrictedTarget(navigationTarget);
    final boolean isLoginView = navigationTarget.equals(loginNavigationTarget());
    final boolean subjectAvailable = SubjectStores.subjectStore()
        .currentSubject(subjectType())
        .isPresent();

    NavigationJSentinelContext ctx = new NavigationJSentinelContext(
        navigationTarget, isRestricted, subjectAvailable, isLoginView);

    NavigationAccessDecision decision = decisionService.evaluateAuthentication(ctx);

    handleAllowedDecision(decision, navigationTarget, isRestricted);
    decisionMapper.apply(
        decision,
        beforeEnterEvent,
        this::loginNavigationTarget,
        this::defaultNavigationTarget);
  }

  private void handleAllowedDecision(NavigationAccessDecision decision,
                                     Class<?> navigationTarget,
                                     boolean isRestricted) {
    if (decision instanceof NavigationAccessDecision.Allowed) {
      if (!isRestricted) {
        notARestrictedTarget(navigationTarget);
      } else {
        logger().info("User is already logged in");
      }
    }
  }

  private boolean isRestrictedTarget(Class<?> navigationTarget) {
    return scanner.scan(navigationTarget)
        .isPresent();
  }

  /**
   * Called when the navigation target does not carry a restriction annotation.
   *
   * @param navigationTarget the unrestricted target class
   */
  public abstract void notARestrictedTarget(Class<?> navigationTarget);

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

  @SuppressWarnings("unchecked")
  private Class<U> subjectType() {
    return (Class<U>) JSentinelServiceResolver
        .<Object, Object>authenticationService()
        .subjectType();
  }
}
