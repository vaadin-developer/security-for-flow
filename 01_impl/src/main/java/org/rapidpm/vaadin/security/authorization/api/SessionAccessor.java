/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rapidpm.vaadin.security.authorization.api;

import com.vaadin.flow.server.VaadinSession;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.frp.model.Result;

import java.util.Objects;

public interface SessionAccessor
    extends HasLogger {

  Class SUBJECT_TYPE = new AuthenticationServiceProvider().load()
      .get()
      .subjectType();

  /**
   * This Class describes the "User" class that is used in the current project to hold the
   * the active User informations. Mostly the class name is something like "User"
   * @param <T> project specific type
   * @return the subject class for the current project
   */
  static <T> Class<T> subjectType() {
    return SUBJECT_TYPE;
  }

  static <T> Result<T> currentSubject() {
    return Result.ofNullable(VaadinSession.getCurrent()
        .getAttribute(subjectType()));
  }

  /**
   *
   * @param subject the instance to set with the informations, something like a User instance
   * @param <T> project specific type of the subject
   */
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
