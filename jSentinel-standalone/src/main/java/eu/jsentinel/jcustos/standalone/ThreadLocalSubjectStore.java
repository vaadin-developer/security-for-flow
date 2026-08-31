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
package eu.jsentinel.jcustos.standalone;

import eu.jsentinel.jcustos.authorization.api.SubjectStore;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * {@link SubjectStore} that keeps the current subject in a thread-local
 * map keyed by subject class. The default for standalone (single-user
 * desktop / CLI) applications.
 * <p>
 * Background-thread propagation is the caller's responsibility: pass the
 * subject (or a {@code Runnable} wrapper that re-binds it) when handing
 * work off to executors, JavaFX {@code Task}s, etc. The store does not
 * inherit across threads — by design, so a fork of a JVM process never
 * silently leaks a security context.
 */
public final class ThreadLocalSubjectStore implements SubjectStore {

  private final ThreadLocal<Map<Class<?>, Object>> store =
      ThreadLocal.withInitial(HashMap::new);

  /** Creates an empty store. Registered via {@code META-INF/services}. */
  public ThreadLocalSubjectStore() {
  }

  @Override
  public <T> Optional<T> currentSubject(Class<T> subjectType) {
    return Optional.ofNullable(subjectType.cast(store.get().get(subjectType)));
  }

  @Override
  public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    store.get().put(subjectType, subject);
  }

  @Override
  public <T> void deleteCurrentSubject(Class<T> subjectType) {
    Map<Class<?>, Object> map = store.get();
    map.remove(subjectType);
    if (map.isEmpty()) {
      store.remove();
    }
  }

  /**
   * Clears every binding on the current thread. Intended for tests and
   * for application shutdown paths.
   */
  public void clear() {
    store.remove();
  }
}
