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
package com.svenruppert.vaadin.security.authorization.vaadin;

import com.svenruppert.vaadin.security.authorization.api.SubjectStore;

import com.vaadin.flow.server.VaadinSession;

import java.util.Objects;
import java.util.Optional;

/**
 * Default {@link SubjectStore} implementation backed by {@link VaadinSession}.
 * <p>
 * Stores the subject as a session attribute keyed by its class type.
 */
public final class VaadinSessionSubjectStore implements SubjectStore {

  /** Creates a new instance. */
  public VaadinSessionSubjectStore() {
  }

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
