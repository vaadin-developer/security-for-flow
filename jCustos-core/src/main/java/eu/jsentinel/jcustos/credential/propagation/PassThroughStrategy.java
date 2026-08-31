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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Optional;

/**
 * Default {@link OutboundTokenStrategy} — forwards a bearer-style
 * inbound token as {@code Authorization: Bearer <value>}.
 *
 * <p>Discipline:
 * <ul>
 *   <li>{@link RefreshToken} is <strong>never</strong> forwarded
 *       (Class-A secret, would leak via the outbound call).</li>
 *   <li>{@link ApiKey} is <strong>not</strong> prefixed with
 *       {@code Bearer }. Consumers register their own
 *       {@code ApiKeyHeaderStrategy} when they want one.</li>
 * </ul>
 *
 * <p>Stateless singleton — share {@link #INSTANCE} across threads.
 *
 * @since 00.74.00
 */
@ExperimentalJCustosApi
public final class PassThroughStrategy implements OutboundTokenStrategy {

  /** Stable lookup key under which the strategy registers. */
  public static final String NAME = "pass-through";

  /** Singleton instance — share across threads. */
  public static final PassThroughStrategy INSTANCE = new PassThroughStrategy();

  private PassThroughStrategy() {
  }

  @Override
  public String name() {
    return NAME;
  }

  @Override
  public Optional<HeaderValue> resolve(OutboundCall call,
                                       Optional<TokenCredential> inbound) {
    // JS-SEC-044 (CWE-522): only forward access-token-shaped credentials; a RefreshToken / ApiKey
    // (Class-A secrets) must never leave as a bearer header. Defer to the single shared decision on
    // TokenCredential so this strategy cannot drift from TokenExchangeStrategy.
    if (inbound.isEmpty() || !inbound.get().isForwardableAsSubjectToken()) {
      return Optional.empty();
    }
    return Optional.of(new HeaderValue("Authorization", "Bearer " + inbound.get().value()));
  }
}
