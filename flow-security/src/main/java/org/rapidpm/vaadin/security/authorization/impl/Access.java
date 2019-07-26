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
package org.rapidpm.vaadin.security.authorization.impl;

import com.vaadin.flow.router.BeforeEnterEvent;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

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
      void exec(BeforeEnterEvent enterEvent) {
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
      void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteToError(errorTarget, errorMessage);
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
      void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteToError(errorTarget);
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
      void exec(BeforeEnterEvent enterEvent) {
        if (asForward) enterEvent.forwardTo(rerouteTarget);
        else enterEvent.rerouteTo(rerouteTarget);
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
      void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteTo(rerouteTarget, parameters);
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
      void exec(BeforeEnterEvent enterEvent) {
        enterEvent.rerouteTo(rerouteTarget, parameter);
      }
    };
  }

  abstract void exec(BeforeEnterEvent enterEvent);
}