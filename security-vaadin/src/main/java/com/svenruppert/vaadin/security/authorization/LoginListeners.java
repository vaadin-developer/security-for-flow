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
package com.svenruppert.vaadin.security.authorization;

import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Resolver for Vaadin login listeners.
 */
public final class LoginListeners {

  private static final AtomicReference<LoginListener<?>> LOGIN_LISTENER_REF =
      new AtomicReference<>();

  private LoginListeners() {
  }

  /**
   * Returns the registered {@link LoginListener}.
   *
   * @param <U> the subject type
   * @return the resolved listener
   */
  @SuppressWarnings("unchecked")
  public static <U> LoginListener<U> loginListener() {
    LoginListener<?> cached = LOGIN_LISTENER_REF.get();
    if (cached != null) {
      return (LoginListener<U>) cached;
    }

    LoginListener<U> loaded = (LoginListener<U>) requireSingleService(
        LoginListener.class,
        ServiceLoader.load(LoginListener.class));

    LOGIN_LISTENER_REF.compareAndSet(null, loaded);
    return (LoginListener<U>) LOGIN_LISTENER_REF.get();
  }

  /**
   * Returns the registered {@link LoginListener}, or empty if none is registered.
   *
   * @param <U> the subject type
   * @return the listener, or empty
   */
  public static <U> Optional<LoginListener<U>> findLoginListener() {
    LoginListener<?> cached = LOGIN_LISTENER_REF.get();
    if (cached != null) {
      return Optional.of((LoginListener<U>) cached);
    }

    Optional<LoginListener> loaded = findSingleService(
        LoginListener.class,
        ServiceLoader.load(LoginListener.class));
    loaded.ifPresent(listener -> LOGIN_LISTENER_REF.compareAndSet(null, listener));
    return Optional.ofNullable((LoginListener<U>) LOGIN_LISTENER_REF.get());
  }

  /**
   * Clears cached listener.
   */
  public static void reset() {
    LOGIN_LISTENER_REF.set(null);
  }

  static <S> S requireSingleService(Class<S> serviceType, Iterable<? extends S> services) {
    return findSingleService(serviceType, services)
        .orElseThrow(() -> missingService(serviceType));
  }

  static <S> Optional<S> findSingleService(Class<S> serviceType, Iterable<? extends S> services) {
    var found = StreamSupport.stream(services.spliterator(), false)
        .toList();
    if (found.isEmpty()) {
      return Optional.empty();
    }
    if (found.size() > 1) {
      throw multipleServices(serviceType, found);
    }
    return Optional.of(found.getFirst());
  }

  private static IllegalStateException missingService(Class<?> serviceType) {
    return new IllegalStateException(
        "Unable to resolve " + serviceType.getSimpleName() + " — "
            + "no implementation found in META-INF/services/"
            + serviceType.getName()
            + ". Provide an implementation and register it "
            + "via the ServiceLoader mechanism.");
  }

  private static IllegalStateException multipleServices(Class<?> serviceType, Iterable<?> services) {
    String implementations = StreamSupport.stream(services.spliterator(), false)
        .map(service -> service.getClass().getName())
        .collect(Collectors.joining(", "));
    return new IllegalStateException(
        "Unable to resolve " + serviceType.getSimpleName() + " — "
            + "multiple implementations found in META-INF/services/"
            + serviceType.getName()
            + ": " + implementations
            + ". Register exactly one implementation to avoid classpath-order dependent security behavior.");
  }
}
