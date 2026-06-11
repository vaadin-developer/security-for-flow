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
package com.svenruppert.jsentinel.credential.propagation.standalone;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.credential.propagation.TokenCredential;
import com.svenruppert.jsentinel.credential.propagation.TokenCredentialStore;

import java.util.Objects;
import java.util.Optional;

/**
 * Standalone-adapter default {@link TokenCredentialStore} backed by a
 * per-thread {@link ThreadLocal} slot. The CLI / desktop demo binds
 * via {@code StandaloneLoginFlow.bindToken(...)}; logout clears.
 *
 * <p>Marked {@code ThreadSafeTokenCredentialStore} (see V00.74 Phase 1
 * prompt 006).
 *
 * <p>Konzept §5.1 allows the duplication between the REST and
 * Standalone copies for V00.74; consolidation into a shared core impl
 * is staged for after Phase 3 only if no per-adapter divergence
 * emerges.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class ThreadLocalTokenCredentialStore implements TokenCredentialStore {

  private static final ThreadLocal<TokenCredential> SLOT = new ThreadLocal<>();

  public ThreadLocalTokenCredentialStore() {
  }

  @Override
  public void bind(TokenCredential credential) {
    SLOT.set(Objects.requireNonNull(credential, "credential"));
  }

  @Override
  public Optional<TokenCredential> current() {
    return Optional.ofNullable(SLOT.get());
  }

  @Override
  public void clear() {
    SLOT.remove();
  }
}
