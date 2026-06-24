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
package com.svenruppert.jsentinel.test;

import com.svenruppert.jsentinel.authentication.AuthenticationService;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * Programmable in-memory {@link AuthenticationService} for tests.
 * <p>
 * Credentials are mapped to subjects via {@link #register(Object, Object)};
 * unknown credentials are rejected by {@link #checkCredentials(Object)}.
 * Generic in both credentials and subject type so tests can reuse the
 * fixture across different domain shapes.
 *
 * <p>Typical use:
 * <pre>
 * FakeAuthenticationService&lt;String, User&gt; auth =
 *     FakeAuthenticationService.&lt;String, User&gt;forType(User.class);
 * auth.register("alice", new User("u-alice", "Alice"));
 * JSentinelServiceResolver.setAuthenticationService...   // wire if needed
 * </pre>
 *
 * @param <C> credentials type
 * @param <U> subject type
 */
public final class FakeAuthenticationService<C, U> implements AuthenticationService<C, U> {

  private final Class<U> subjectType;
  // R040: shipped fixture — back the registry with a thread-safe map so
  // consumers exercising it from concurrent tests cannot corrupt it. register()
  // already rejects null credentials/subjects, so ConcurrentHashMap's
  // no-null-key/value constraint is never hit.
  private final Map<C, U> registry = new ConcurrentHashMap<>();
  private final Function<C, U> fallbackLoader;

  private FakeAuthenticationService(Class<U> subjectType, Function<C, U> fallbackLoader) {
    this.subjectType = requireNonNull(subjectType, "subjectType must not be null");
    this.fallbackLoader = fallbackLoader;
  }

  /**
   * Creates a fake that rejects every credential not explicitly
   * registered.
   *
   * @param subjectType subject class token; must not be {@code null}
   * @param <C>         credentials type
   * @param <U>         subject type
   * @return fake
   */
  public static <C, U> FakeAuthenticationService<C, U> forType(Class<U> subjectType) {
    return new FakeAuthenticationService<>(subjectType, null);
  }

  /**
   * Creates a fake that, on unregistered credentials, delegates to
   * {@code fallbackLoader} (e.g. for parametric tests). The fallback
   * may return {@code null}; {@link #checkCredentials(Object)} treats
   * a {@code null}-returning fallback as a rejection.
   *
   * @param subjectType    subject class token
   * @param fallbackLoader loader for unregistered credentials
   * @param <C>            credentials type
   * @param <U>            subject type
   * @return fake
   */
  public static <C, U> FakeAuthenticationService<C, U> withFallback(
      Class<U> subjectType, Function<C, U> fallbackLoader) {
    return new FakeAuthenticationService<>(subjectType,
        requireNonNull(fallbackLoader, "fallbackLoader must not be null"));
  }

  /**
   * Registers a credentials → subject mapping. Re-registering replaces
   * the previous entry.
   *
   * @param credentials credentials key; must not be {@code null}
   * @param subject     subject value; must not be {@code null}
   * @return this fake
   */
  public FakeAuthenticationService<C, U> register(C credentials, U subject) {
    requireNonNull(credentials, "credentials must not be null");
    requireNonNull(subject, "subject must not be null");
    registry.put(credentials, subject);
    return this;
  }

  @Override
  public boolean checkCredentials(C credentials) {
    if (credentials == null) {
      return false;
    }
    if (registry.containsKey(credentials)) {
      return true;
    }
    return fallbackLoader != null && fallbackLoader.apply(credentials) != null;
  }

  @Override
  public U loadSubject(C credentials) {
    U registered = credentials == null ? null : registry.get(credentials);
    if (registered != null) {
      return registered;
    }
    if (fallbackLoader != null) {
      return fallbackLoader.apply(credentials);
    }
    return null;
  }

  @Override
  public Class<U> subjectType() {
    return subjectType;
  }
}
