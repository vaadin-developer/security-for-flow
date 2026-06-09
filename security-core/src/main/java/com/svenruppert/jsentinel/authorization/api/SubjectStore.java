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
package com.svenruppert.jsentinel.authorization.api;

import java.util.Optional;

/**
 * Abstraction for storing and retrieving the current security subject (user).
 * <p>
 * This decouples subject management from adapter-specific session
 * implementations.
 *
 * @see SubjectStores
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
