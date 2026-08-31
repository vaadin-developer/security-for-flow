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
package eu.jsentinel.jcustos.credential.propagation.vaadin;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import com.vaadin.flow.server.VaadinSession;

import java.util.Objects;
import java.util.Optional;

/**
 * Vaadin-adapter default {@link TokenCredentialStore} backed by
 * {@link VaadinSession}.
 *
 * <p>Stores the credential as a session attribute under a private
 * string key. Throws {@link IllegalStateException} on
 * {@link #bind(TokenCredential)} when called outside an active Vaadin
 * session — the demo login flow runs inside a UI request thread.
 * {@link #current()} and {@link #clear()} are no-ops outside a session.
 *
 * <p>Registered via {@code META-INF/services/...TokenCredentialStore}
 * — the Vaadin-adapter module does not (yet) wire the
 * {@code jCustos-autoservice-processor}, so registration is
 * hand-written next to the existing {@code SubjectStore} entry.
 *
 * <p>Single-thread per UI; not marked
 * {@code ThreadSafeTokenCredentialStore} — background-thread access is
 * an application bug, not a framework concern.
 *
 * @since 00.74.00
 */
@ExperimentalJCustosApi
public final class VaadinSessionTokenCredentialStore implements TokenCredentialStore {

  static final String ATTR_KEY =
      "eu.jsentinel.jcustos.credential.propagation.TokenCredential";

  public VaadinSessionTokenCredentialStore() {
  }

  @Override
  public void bind(TokenCredential credential) {
    Objects.requireNonNull(credential, "credential");
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      throw new IllegalStateException(
          "VaadinSessionTokenCredentialStore.bind called outside an active VaadinSession");
    }
    session.setAttribute(ATTR_KEY, credential);
  }

  @Override
  public Optional<TokenCredential> current() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return Optional.empty();
    }
    Object attr = session.getAttribute(ATTR_KEY);
    return attr instanceof TokenCredential c ? Optional.of(c) : Optional.empty();
  }

  @Override
  public void clear() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) {
      session.setAttribute(ATTR_KEY, null);
    }
  }
}
