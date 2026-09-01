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
package eu.jsentinel.jcustos.credential.propagation;


import java.util.Objects;
import java.util.Optional;

/**
 * Thread-local bridge between the V00.74 wrapper (runtime
 * {@code PropagatingProxy} or compile-time {@code <Type>Propagating})
 * and the application's HTTP client. The wrapper
 * {@link #bind(HeaderValue) bind}s a header, runs the delegate, and
 * {@link #clear()}s in a {@code finally}. The HTTP client reads
 * {@link #current()} just before sending and applies it on the request.
 *
 * <p>Two-line interceptor pattern (JDK {@link java.net.http.HttpClient}):
 * <pre>{@code
 * OutboundHeaderContext.current()
 *     .ifPresent(h -> requestBuilder.header(h.name(), h.value()));
 * }</pre>
 *
 * <p>Single slot per thread, never inherited. Nested
 * {@link #bind(HeaderValue) bind}s raise — the wrapper resets in
 * {@code finally}, so a second bind without an intervening clear is a
 * programming error.
 *
 * @since 00.74.00
 */
public final class OutboundHeaderContext {

  private static final ThreadLocal<HeaderValue> SLOT = new ThreadLocal<>();

  private OutboundHeaderContext() {
    throw new AssertionError("no instances");
  }

  /**
   * Bind a header to the current thread.
   *
   * @param value the header to bind; non-null
   * @throws IllegalStateException if the slot is already bound — a
   *                                second bind without an intervening
   *                                {@link #clear()} is a programming error
   */
  public static void bind(HeaderValue value) {
    Objects.requireNonNull(value, "value");
    if (SLOT.get() != null) {
      throw new IllegalStateException(
          "OutboundHeaderContext already bound on this thread — nested bind() forbidden");
    }
    SLOT.set(value);
  }

  /**
   * @return the currently bound header, or empty
   */
  public static Optional<HeaderValue> current() {
    return Optional.ofNullable(SLOT.get());
  }

  /**
   * Reset the slot. Idempotent — repeated calls are no-ops.
   */
  public static void clear() {
    SLOT.remove();
  }
}
