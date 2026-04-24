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
package com.svenruppert.vaadin.security.authorization.api;

import java.util.Optional;

/**
 * Abstraction for storing and retrieving the current security subject (user).
 * <p>
 * This decouples subject management from the Vaadin session, allowing
 * core security logic to be unit-tested without a running Vaadin application.
 * <p>
 * The default implementation {@link VaadinSessionSubjectStore} delegates
 * to {@link com.vaadin.flow.server.VaadinSession}.
 *
 * @see VaadinSessionSubjectStore
 * @see SessionAccessor
 */
public interface SubjectStore {

  /**
   * Returns the current subject, if one is present in the store.
   *
   * @param subjectType the expected class of the subject
   * @param <T>         the subject type
   * @return an {@link Optional} containing the subject, or empty if absent
   */
  <T> Optional<T> currentSubject(Class<T> subjectType);

  /**
   * Stores the given subject as the current subject.
   *
   * @param subject     the subject to store; must not be null
   * @param subjectType the class token for the subject type
   * @param <T>         the subject type
   */
  <T> void setCurrentSubject(T subject, Class<T> subjectType);

  /**
   * Removes the current subject from the store.
   *
   * @param subjectType the class token for the subject type
   * @param <T>         the subject type
   */
  <T> void deleteCurrentSubject(Class<T> subjectType);

  /**
   * Returns whether a subject is currently present in the store.
   *
   * @param subjectType the class token for the subject type
   * @param <T>         the subject type
   * @return true if a subject is stored
   */
  default <T> boolean hasSubject(Class<T> subjectType) {
    return currentSubject(subjectType).isPresent();
  }
}