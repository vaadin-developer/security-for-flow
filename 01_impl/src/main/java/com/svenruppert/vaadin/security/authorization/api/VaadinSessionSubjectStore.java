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

import com.vaadin.flow.server.VaadinSession;

import java.util.Objects;
import java.util.Optional;

/**
 * Default {@link SubjectStore} implementation backed by {@link VaadinSession}.
 * <p>
 * Stores the subject as a session attribute keyed by its class type.
 */
public final class VaadinSessionSubjectStore implements SubjectStore {

  @Override
  public <T> Optional<T> currentSubject(Class<T> subjectType) {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) return Optional.empty();
    return Optional.ofNullable(session.getAttribute(subjectType));
  }

  @Override
  public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    Objects.requireNonNull(subject, "subject must not be null");
    VaadinSession session = VaadinSession.getCurrent();
    Objects.requireNonNull(session,
        "No active VaadinSession — setCurrentSubject must be called from a Vaadin request thread");
    session.setAttribute(subjectType, subject);
  }

  @Override
  public <T> void deleteCurrentSubject(Class<T> subjectType) {
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) {
      session.setAttribute(subjectType, null);
    }
  }
}