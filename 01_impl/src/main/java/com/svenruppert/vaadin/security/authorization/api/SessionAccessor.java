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
 * The subject type is lazily resolved from the registered
 * {@link AuthenticationService} via {@link SecurityServiceResolver}.
 * For testing, the subject type can be explicitly set via
 * {@link #setSubjectType(Class)}.
 *
 * @see SubjectStore
 * @see VaadinSessionSubjectStore
 */
public final class SessionAccessor {

  private static final AtomicReference<SubjectStore> STORE_REF =
      new AtomicReference<>(new VaadinSessionSubjectStore());

  private static final AtomicReference<Class<?>> SUBJECT_TYPE_REF =
      new AtomicReference<>();

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

  /**
   * Explicitly sets the subject type.
   * Intended for testing or environments where the
   * {@link AuthenticationService} SPI is not registered.
   */
  public static void setSubjectType(Class<?> type) {
    SUBJECT_TYPE_REF.set(type);
  }

  /**
   * Resets both the subject store and the cached subject type
   * to their defaults. Intended for test cleanup.
   */
  public static void reset() {
    STORE_REF.set(new VaadinSessionSubjectStore());
    SUBJECT_TYPE_REF.set(null);
  }

  @SuppressWarnings("unchecked")
  private static <T> Class<T> subjectType() {
    Class<?> cached = SUBJECT_TYPE_REF.get();
    if (cached != null) {
      return (Class<T>) cached;
    }
    Class<?> resolved = SecurityServiceResolver
        .<Object, Object>authenticationService()
        .subjectType();
    SUBJECT_TYPE_REF.compareAndSet(null, resolved);
    return (Class<T>) SUBJECT_TYPE_REF.get();
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
}
