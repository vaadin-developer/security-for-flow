package org.rapidpm.vaadin.security.authorization.api;

import com.vaadin.flow.server.VaadinSession;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.frp.model.Result;

import java.util.Objects;

public interface SessionAccessor
    extends HasLogger {

  Class SUBJECT_TYPE = new AuthenticationServiceProvider().load()
                                                          .subjectType();

  /**
   * This Class describes the "User" class that is used in the current project to hold the
   * the active User informations. Mostly the class name is something like "User"
   *
   * @return the subject class for the current project
   */
  static <T> Class<T> subjectType() {
    return SUBJECT_TYPE;
  }

  static <T> Result<T> currentSubject() {
    return Result.ofNullable(VaadinSession.getCurrent()
                                          .getAttribute(subjectType()));
  }

  static <T> void setCurrentSubject(T subject) {
    Objects.requireNonNull(subject);
//    final Object cast = subjectType().cast(subject);
    VaadinSession.getCurrent()
                 .setAttribute(subjectType(), subject);
  }

  static void deleteCurrentSubject() {
    VaadinSession.getCurrent()
                 .setAttribute(subjectType(), null);
  }


}
