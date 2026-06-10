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
package com.svenruppert.jsentinel.credential.propagation;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Optional;

/**
 * Persistence-neutral store for the current subject's
 * {@link TokenCredential}. Inbound resolvers (V00.74 RestSubjectResolver
 * extension, V00.80 OIDC bridge) populate it; outbound wrappers
 * ({@code @PropagateToken}, {@code PropagatingProxy}) read from it.
 *
 * <p>Adapter-specific defaults ship in each adapter module:
 * <ul>
 *   <li>{@code VaadinSessionTokenCredentialStore} ({@code jSentinel-vaadin})
 *       — backed by {@code VaadinSession}.</li>
 *   <li>{@code ThreadLocalTokenCredentialStore} ({@code jSentinel-rest})
 *       — backed by a per-request {@code ThreadLocal}, scoped by
 *       {@code RestTokenCredentialFilter}.</li>
 *   <li>{@code ThreadLocalTokenCredentialStore} ({@code jSentinel-standalone})
 *       — backed by a per-thread {@code ThreadLocal}, scoped by
 *       {@code StandaloneLoginFlow}.</li>
 * </ul>
 *
 * <p>Consumers override the SPI default through the
 * {@code .propagation(p -> p.credentialStore(myStore))} sub-builder
 * (V00.74 Prompt 015 / 016).
 *
 * <p>The V00.74 contract intentionally omits a {@code refresh()}
 * surface — {@code RefreshableTokenCredentialStore extends
 * TokenCredentialStore} is staged for V00.76 (Konzept §6.4) so adding
 * it later does not break this contract.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi("V00.74 token propagation; stable promotion staged for V00.76")
public interface TokenCredentialStore {

  /**
   * Replace any current entry with {@code credential}.
   *
   * @param credential the new entry (non-null)
   */
  void bind(TokenCredential credential);

  /**
   * @return the current entry, or empty
   */
  Optional<TokenCredential> current();

  /**
   * Reset to the empty state. Idempotent — repeated calls are no-ops.
   */
  void clear();
}
