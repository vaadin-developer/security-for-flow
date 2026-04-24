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

import com.svenruppert.functional.model.Result;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Static convenience facade for subject management.
 * <p>
 * Delegates to a {@link SubjectStore} instance. By default this is a
 * {@link VaadinSessionSubjectStore}, but it can be replaced for testing
 * via {@link #setSubjectStore(SubjectStore)}.
 * <p>
 * The public API ({@code currentSubject()}, {@code setCurrentSubject(...)},
 * {@code deleteCurrentSubject()}) is unchanged from prior versions.
 *
 * @see SubjectStore
 * @see VaadinSessionSubjectStore
 */
public final class SessionAccessor {

  private static final AtomicReference<SubjectStore> STORE_REF =
      new AtomicReference<>(new VaadinSessionSubjectStore());

  private SessionAccessor() {
  }

  /**
   * Replaces the active {@link SubjectStore}.
   * Intended for testing or non-Vaadin environments.
   */
  public static void setSubjectStore(SubjectStore store) {
    STORE_REF.set(store);
  }

  /**
   * Returns the active {@link SubjectStore}.
   */
  public static SubjectStore subjectStore() {
    return STORE_REF.get();
  }

  @SuppressWarnings("unchecked")
  private static <T> Class<T> subjectType() {
    return (Class<T>) SubjectTypeHolder.SUBJECT_TYPE;
  }

  @SuppressWarnings("unchecked")
  public static <T> Result<T> currentSubject() {
    Class<T> type = subjectType();
    return Result.ofNullable(
        (T) STORE_REF.get().currentSubject(type).orElse(null));
  }

  @SuppressWarnings("unchecked")
  public static <T> void setCurrentSubject(T subject) {
    Class<T> type = subjectType();
    STORE_REF.get().setCurrentSubject(subject, type);
  }

  public static void deleteCurrentSubject() {
    STORE_REF.get().deleteCurrentSubject(subjectType());
  }

  private static final class SubjectTypeHolder {
    static final Class<?> SUBJECT_TYPE = SecurityServiceResolver
        .<Object, Object>authenticationService()
        .subjectType();
  }
}