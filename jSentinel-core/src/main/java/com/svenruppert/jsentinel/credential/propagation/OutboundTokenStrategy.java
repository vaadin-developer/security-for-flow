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
 * Pluggable "how does the inbound token reach the downstream call" SPI.
 *
 * <p>V00.74 ships {@link PassThroughStrategy} as the core default. The
 * opt-in {@code jSentinel-propagation-oidc} module adds
 * {@code TokenExchangeStrategy} (RFC 8693) and
 * {@code ClientCredentialsStrategy} (RFC 6749 §4.4). Consumers register
 * additional strategies via the {@code .propagation(...)} bootstrap
 * sub-builder.
 *
 * <p>Implementations return {@link Optional#empty()} when no header
 * should be set — empty is the explicit "skip" answer, not a soft
 * failure. Hard failures (e.g. token-exchange endpoint returns 401)
 * throw a runtime exception so the outbound call aborts loudly; never
 * silently downgrades to the no-header path.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi("V00.74 token propagation; stable promotion staged for V00.76")
public interface OutboundTokenStrategy {

  /**
   * @return stable lookup key (e.g. {@code "pass-through"},
   *         {@code "exchange"}); used by
   *         {@code @PropagateToken(strategy = …)}
   */
  String name();

  /**
   * @param call    the outbound call about to fire
   * @param inbound the current inbound credential, if any
   * @return the header to bind, or empty to skip
   */
  Optional<HeaderValue> resolve(OutboundCall call, Optional<TokenCredential> inbound);
}
