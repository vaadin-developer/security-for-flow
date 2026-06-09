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

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link SubjectStore} for unit testing.
 * No Vaadin dependencies required.
 */
public class InMemorySubjectStore implements SubjectStore {

  private final Map<Class<?>, Object> store = new ConcurrentHashMap<>();

  @Override
  @SuppressWarnings("unchecked")
  public <T> Optional<T> currentSubject(Class<T> subjectType) {
    return Optional.ofNullable((T) store.get(subjectType));
  }

  @Override
  public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    store.put(subjectType, subject);
  }

  @Override
  public <T> void deleteCurrentSubject(Class<T> subjectType) {
    store.remove(subjectType);
  }

  public void clear() {
    store.clear();
  }
}
