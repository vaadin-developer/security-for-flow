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
package com.svenruppert.jsentinel.authorization.impl;

import com.svenruppert.jsentinel.authorization.LoginView;
import com.svenruppert.jsentinel.authorization.navigation.NavigationAccessDecision;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.BeforeEnterEvent;

import java.util.function.Supplier;

/**
 * Maps authentication-phase navigation decisions to Vaadin navigation operations.
 */
public final class VaadinNavigationAccessDecisionMapper {

  /** Creates a new mapper. */
  public VaadinNavigationAccessDecisionMapper() {
  }

  /**
   * Applies a navigation access decision to a Vaadin before-enter event.
   *
   * @param decision      the authentication-phase decision
   * @param event         the Vaadin event
   * @param loginTarget   supplies the login target class
   * @param defaultTarget supplies the default target class for already authenticated users
   */
  public void apply(NavigationAccessDecision decision,
                    BeforeEnterEvent event,
                    Supplier<Class<? extends LoginView>> loginTarget,
                    Supplier<Class<? extends Component>> defaultTarget) {
    switch (decision) {
      case NavigationAccessDecision.Allowed() -> { /* nothing to do */ }
      case NavigationAccessDecision.LoginRequired() -> event.forwardTo(loginTarget.get());
      case NavigationAccessDecision.AlreadyLoggedIn() -> event.forwardTo(defaultTarget.get());
      case NavigationAccessDecision.AccessDenied(String route, boolean asForward) -> {
        if (asForward) {
          event.forwardTo(route);
        } else {
          event.rerouteTo(route);
        }
      }
    }
  }
}
