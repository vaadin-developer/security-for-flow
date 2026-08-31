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
package eu.jsentinel.jcustos.authorization.api;

import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Resolver for the active {@link SubjectStore}.
 * <p>
 * The concrete store is provided through Java {@link ServiceLoader}. Vaadin
 * applications get their implementation from the adapter module.
 */
public final class SubjectStores {

  private static final AtomicReference<SubjectStore> SUBJECT_STORE_REF =
      new AtomicReference<>();

  private SubjectStores() {
  }

  /**
   * Returns the registered {@link SubjectStore}.
   *
   * @return the resolved subject store
   */
  public static SubjectStore subjectStore() {
    SubjectStore cached = SUBJECT_STORE_REF.get();
    if (cached != null) {
      return cached;
    }

    SubjectStore loaded = JSentinelServiceResolver.requireSingleService(
        SubjectStore.class,
        ServiceLoader.load(SubjectStore.class));

    SUBJECT_STORE_REF.compareAndSet(null, loaded);
    return SUBJECT_STORE_REF.get();
  }

  /**
   * Returns the registered {@link SubjectStore}, or empty if none is registered.
   *
   * @return the subject store, or empty
   */
  public static Optional<SubjectStore> findSubjectStore() {
    SubjectStore cached = SUBJECT_STORE_REF.get();
    if (cached != null) {
      return Optional.of(cached);
    }

    Optional<SubjectStore> loaded = JSentinelServiceResolver.findSingleService(
        SubjectStore.class,
        ServiceLoader.load(SubjectStore.class));
    loaded.ifPresent(store -> SUBJECT_STORE_REF.compareAndSet(null, store));
    return Optional.ofNullable(SUBJECT_STORE_REF.get());
  }

  /**
   * Replaces the active store. Intended for tests.
   *
   * @param store the subject store
   */
  public static void setSubjectStore(SubjectStore store) {
    SUBJECT_STORE_REF.set(store);
  }

  /**
   * Clears the cached store.
   */
  public static void reset() {
    SUBJECT_STORE_REF.set(null);
  }
}
