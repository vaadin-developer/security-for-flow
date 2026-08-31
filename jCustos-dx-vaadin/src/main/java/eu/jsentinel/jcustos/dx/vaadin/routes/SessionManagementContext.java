/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.vaadin.routes;

import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStore;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Static holder that the V00.73 Vaadin bootstrap uses to publish the
 * configured {@link SessionStore} and the optional revoke callback
 * for {@link SessionManagementRoute} to read at route construction
 * time (Vaadin instantiates {@code @Route} classes via their no-arg
 * constructor).
 *
 * <p>Package-private accessors are used by
 * {@link SessionManagementRoute}; the {@code set...} methods are
 * called from the bootstrap implementation.
 *
 * <p><strong>Thread-safety.</strong> The holder is process-wide.
 * A second bootstrap call replaces the previous configuration —
 * matches the "single-use builder" contract on
 * {@code VaadinJCustosBootstrapImpl}.
 *
 * @since 00.73.00
 */
public final class SessionManagementContext {

  private static final AtomicReference<SessionStore> STORE = new AtomicReference<>();
  private static final AtomicReference<Consumer<SessionRecord>> REVOKE = new AtomicReference<>();

  private SessionManagementContext() {
    throw new AssertionError("no instances");
  }

  /**
   * Publishes the SessionStore + optional revoke callback that
   * {@link SessionManagementRoute} should consume.
   *
   * @param store  the configured SessionStore; never {@code null}
   * @param revoke revoke handler; {@code null} → drop-from-store on revoke
   */
  public static void publish(SessionStore store, Consumer<SessionRecord> revoke) {
    STORE.set(Objects.requireNonNull(store, "store"));
    REVOKE.set(revoke);
  }

  /** Test helper: reset the holder. */
  public static void reset() {
    STORE.set(null);
    REVOKE.set(null);
  }

  static Optional<SessionStore> store() {
    return Optional.ofNullable(STORE.get());
  }

  static Consumer<SessionRecord> revoke() {
    Consumer<SessionRecord> registered = REVOKE.get();
    return registered != null ? registered : SessionManagementContext::dropFromStore;
  }

  private static void dropFromStore(SessionRecord record) {
    store().ifPresent(s -> s.delete(record.sessionId()));
  }
}
