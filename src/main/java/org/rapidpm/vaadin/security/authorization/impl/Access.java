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