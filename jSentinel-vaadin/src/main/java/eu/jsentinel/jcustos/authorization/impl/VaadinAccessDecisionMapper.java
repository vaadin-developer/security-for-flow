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
package eu.jsentinel.jcustos.authorization.impl;

import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import com.vaadin.flow.router.BeforeEnterEvent;

/**
 * Maps core access decisions to Vaadin navigation operations.
 */
public final class VaadinAccessDecisionMapper {

  /** Creates a new mapper. */
  public VaadinAccessDecisionMapper() {
  }

  /**
   * Applies an access decision to a Vaadin before-enter event.
   *
   * @param decision the core decision
   * @param event    the Vaadin event
   */
  public void apply(AccessDecision decision, BeforeEnterEvent event) {
    switch (decision) {
      case AccessDecision.Granted() -> { /* nothing to do */ }
      case AccessDecision.Reroute(String route, boolean asForward) -> {
        if (asForward) {
          event.forwardTo(route);
        } else {
          event.rerouteTo(route);
        }
      }
      case AccessDecision.RerouteToError(Class<? extends Exception> errorType, String msg) -> {
        if (msg != null) {
          try {
            event.rerouteToError(errorType.getDeclaredConstructor().newInstance(), msg);
          } catch (ReflectiveOperationException e) {
            event.rerouteToError(new RuntimeException("Access denied", e), msg);
          }
        } else {
          event.rerouteToError(errorType);
        }
      }
      case AccessDecision.RerouteWithParameter<?> reroute ->
          event.rerouteTo(reroute.target(), reroute.parameter());
      case AccessDecision.RerouteWithParameters<?> reroute ->
          event.rerouteTo(reroute.target(), reroute.parameters());
    }
  }
}
