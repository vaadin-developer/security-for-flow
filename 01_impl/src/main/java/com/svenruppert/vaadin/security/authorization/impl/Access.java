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
package com.svenruppert.vaadin.security.authorization.impl;

import com.svenruppert.vaadin.security.authorization.navigation.AuthorizationDecision;
import com.vaadin.flow.router.BeforeEnterEvent;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Legacy access decision type that directly mutates {@link BeforeEnterEvent}.
 * <p>
 * New code should prefer {@link AuthorizationDecision}, which is a pure
 * Vaadin-free value type. The Vaadin adapter layer translates
 * {@code AuthorizationDecision} into event mutations.
 *
 * @deprecated Use {@link AuthorizationDecision} instead. This class remains
 *     for backward compatibility with existing {@code AccessEvaluator}
 *     implementations.
 */
@Deprecated(since = "0.50.0", forRemoval = false)
public abstract class Access
    implements Serializable {

  private static final long serialVersionUID = -5142617945164430893L;

  private Access() {
  }

  /**
   * a granted access, the user will be allowed to enter the route-target.
   *
   * @return the granted access
   */
  public static Access granted() {
    return new Access() {
      @Override
      public void exec(BeforeEnterEvent enterEvent) {
      }

      @Override
      public AuthorizationDecision toDecision() {
        return AuthorizationDecision.granted();
      }
    };
  }

  /**
   * A restricted access that will call {@link BeforeEnterEvent#rerouteToError(Exception,
   * String)}
   *
   * @param errorTarget  see {@link BeforeEnterEvent#rerouteToError(Exception, String)}
   * @param errorMessage see {@link BeforeEnterEvent#rerouteToError(Exception, String)}
   * @return the restricted Access
   */
  public static Access restricted(Exception errorTarget, String errorMessage) {
    Objects.requireNonNull(errorTarget, "errorTarget must not be null");

    return new Access() {
      @Override
      public void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteToError(errorTarget, errorMessage);
      }

      @Override
      public AuthorizationDecision toDecision() {
        return AuthorizationDecision.deniedWithError(errorTarget.getClass(), errorMessage);
      }
    };
  }

  /**
   * A restricted access that will call {@link BeforeEnterEvent#rerouteToError(Class)}
   *
   * @param errorTarget see {@link BeforeEnterEvent#rerouteToError(Class)}
   * @return the restricted Access
   */
  public static Access restricted(Class<? extends Exception> errorTarget) {
    Objects.requireNonNull(errorTarget, "errorTarget must not be null");

    return new Access() {
      @Override
      public void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteToError(errorTarget);
      }

      @Override
      public AuthorizationDecision toDecision() {
        return AuthorizationDecision.deniedWithError(errorTarget, null);
      }
    };
  }

  /**
   * A restricted access that will call {@link BeforeEnterEvent#rerouteTo(String)}
   *
   * @param rerouteTarget see {@link BeforeEnterEvent#rerouteTo(String)}
   * @param asForward switch between forward and reroute
   * @return the restricted Access
   */
  public static Access restricted(String rerouteTarget, boolean asForward) {
    Objects.requireNonNull(rerouteTarget, "rerouteTarget must not be null");

    return new Access() {
      @Override
      public void exec(BeforeEnterEvent enterEvent) {
        if (asForward) enterEvent.forwardTo(rerouteTarget);
        else enterEvent.rerouteTo(rerouteTarget);
      }

      @Override
      public AuthorizationDecision toDecision() {
        return AuthorizationDecision.denied(rerouteTarget, asForward);
      }
    };
  }


  /**
   * A restricted access that will call {@link BeforeEnterEvent#rerouteTo(String, List)}
   *
   * @param rerouteTarget see {@link BeforeEnterEvent#rerouteTo(String, List)}
   * @param parameters project specific class type
   * @param <T> project specific class type
   * @return the restricted Access
   */
  public static <T> Access restricted(String rerouteTarget, List<T> parameters) {
    Objects.requireNonNull(rerouteTarget, "rerouteTarget must not be null");
    Objects.requireNonNull(parameters, "parameters must not be null");

    return new Access() {
      @Override
      public void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteTo(rerouteTarget, parameters);
      }

      @Override
      public AuthorizationDecision toDecision() {
        return AuthorizationDecision.denied(rerouteTarget, false);
      }
    };
  }

  /**
   * A restricted access that will call {@link BeforeEnterEvent#rerouteTo(String, Object)}
   *
   * @param rerouteTarget see {@link BeforeEnterEvent#rerouteTo(String, Object)}
   * @param parameter project specific class type
   * @param <T> project specific class type
   * @return the restricted Access
   */
  public static <T> Access restricted(String rerouteTarget, T parameter) {
    Objects.requireNonNull(rerouteTarget, "rerouteTarget must not be null");
    Objects.requireNonNull(parameter, "parameters must not be null");

    return new Access() {
      @Override
      public void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteTo(rerouteTarget, parameter);
      }

      @Override
      public AuthorizationDecision toDecision() {
        return AuthorizationDecision.denied(rerouteTarget, false);
      }
    };
  }

  /**
   * Applies this access decision to the given event.
   *
   * @deprecated Prefer using {@link #toDecision()} and letting the
   *     Vaadin adapter layer apply the decision.
   */
  @Deprecated(since = "0.50.0", forRemoval = false)
  public abstract void exec(BeforeEnterEvent enterEvent);

  /**
   * Converts this legacy {@code Access} to the new {@link AuthorizationDecision}
   * value type.
   *
   * @return the equivalent authorization decision
   */
  public abstract AuthorizationDecision toDecision();
}
