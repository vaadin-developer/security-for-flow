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

import java.util.Objects;

/**
 * Adapter-neutral default {@link LogoutService} implementation. Drops the
 * current subject from the {@link SubjectStore}. Does not invalidate
 * sessions and does not navigate — those are adapter concerns.
 *
 * @param <U> subject type
 */
public final class SubjectClearingLogoutService<U> implements LogoutService {

  private final SubjectStore subjectStore;
  private final Class<U> subjectType;

  public SubjectClearingLogoutService(SubjectStore subjectStore, Class<U> subjectType) {
    this.subjectStore = Objects.requireNonNull(subjectStore, "subjectStore");
    this.subjectType = Objects.requireNonNull(subjectType, "subjectType");
  }

  @Override
  public void logout(LogoutContext context) {
    Objects.requireNonNull(context, "context");
    subjectStore.deleteCurrentSubject(subjectType);
  }
}
