/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.persistence.eclipsestore.testsupport;

import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/**
 * Test-support factory that wraps a real {@link EmbeddedStorageManager}
 * in a forwarding JDK proxy whose {@code shutdown()} call throws a
 * caller-supplied {@link RuntimeException}. Every other method is
 * forwarded unchanged to the real delegate so the rest of the
 * Eclipse-Store API keeps working.
 *
 * <p>This is intentionally NOT a mocking-framework construct. It uses
 * only {@link java.lang.reflect.Proxy} (JDK reflection API — the same
 * primitive that drives {@code SecuredProxy.wrap(...)} elsewhere in
 * jCustos) and a plain {@code InvocationHandler}. Konzept §9
 * "No-Mocks-Disziplin" bans mocking libraries (Mockito, EasyMock,
 * PowerMock); it does not forbid concrete real-class delegators.
 *
 * <p>Need: the lifecycle tests for {@code JCustosStoragePair.close()}
 * must drive a deterministic {@code shutdown()} failure. Eclipse
 * Store's own {@code shutdown()} is idempotent (returns {@code false}
 * on the second call, never throws), so the "pre-shutdown trick"
 * cannot produce a throw on demand.
 */
public final class ShutdownFailingStorageManager {

  private ShutdownFailingStorageManager() {
    // utility class — never instantiated
  }

  /**
   * Wraps the delegate. Calling {@code shutdown()} on the returned
   * manager throws {@code toThrow}; every other method is forwarded
   * directly to {@code delegate}.
   *
   * @param delegate the real Eclipse-Store manager
   * @param toThrow  exception to throw from {@code shutdown()}
   * @return a JDK proxy implementing {@link EmbeddedStorageManager}
   */
  public static EmbeddedStorageManager wrap(EmbeddedStorageManager delegate,
                                            RuntimeException toThrow) {
    return (EmbeddedStorageManager) Proxy.newProxyInstance(
        ShutdownFailingStorageManager.class.getClassLoader(),
        new Class<?>[]{EmbeddedStorageManager.class},
        (proxy, method, args) -> {
          if ("shutdown".equals(method.getName())
              && (args == null || args.length == 0)) {
            throw toThrow;
          }
          try {
            return method.invoke(delegate, args);
          } catch (InvocationTargetException invocationFailure) {
            // Unwrap so the caller sees the real cause, not the
            // reflection wrapper.
            throw invocationFailure.getCause();
          }
        });
  }
}
