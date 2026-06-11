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

import com.svenruppert.jsentinel.annotations.PropagateToken;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;

import java.util.Optional;

/**
 * Pluggable advisor that turns a {@link PropagateToken}-annotated call
 * + the current {@link TokenCredential} into an {@link HeaderValue} to
 * bind on the outbound HTTP request.
 *
 * <p>Crucially, this is <strong>not</strong> an
 * {@code AccessEvaluator}: it never produces an access decision. The
 * advisor either returns a header (bind it) or empty (skip).
 *
 * <p>{@link Default} composes
 * {@link com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver#findOutboundTokenStrategy(String)}
 * with the supplied store. Prompt 008 lands the {@code Default} body;
 * this file ships the contract so {@code @PropagateToken}'s meta
 * reference resolves.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi("V00.74 token propagation; stable promotion staged for V00.76")
public interface PropagateTokenAdvisor {

  /**
   * @param annotation the resolved annotation
   * @param call       the outbound call about to fire
   * @param store      the active credential store
   * @return the header to bind, or empty to skip
   */
  Optional<HeaderValue> adviseFor(PropagateToken annotation,
                                  OutboundCall call,
                                  TokenCredentialStore store);

  /**
   * Stateless default advisor: looks up the strategy by
   * {@link PropagateToken#strategy()} via
   * {@link JSentinelServiceResolver#findOutboundTokenStrategy(String)},
   * calls its {@code resolve} with the store's current credential, and
   * — when {@link PropagateToken#header()} is non-empty — overrides the
   * strategy's chosen header name.
   *
   * <p>An unregistered strategy returns {@link Optional#empty()}; the
   * advisor never raises. {@code STRICT}-mode diagnostics surface the
   * {@code propagation/unknown-strategy} code separately (V00.74 Prompt
   * 018) so this call stays side-effect-free.
   */
  final class Default implements PropagateTokenAdvisor {

    /** Shared singleton; advisor is stateless. */
    public static final Default INSTANCE = new Default();

    private Default() {
    }

    @Override
    public Optional<HeaderValue> adviseFor(PropagateToken annotation,
                                          OutboundCall call,
                                          TokenCredentialStore store) {
      Optional<OutboundTokenStrategy> strategy =
          JSentinelServiceResolver.findOutboundTokenStrategy(annotation.strategy());
      if (strategy.isEmpty()) {
        return Optional.empty();
      }
      Optional<HeaderValue> result = strategy.get().resolve(call, store.current());
      if (result.isEmpty()) {
        return result;
      }
      String overrideName = annotation.header();
      if (overrideName.isEmpty() || overrideName.equals(result.get().name())) {
        return result;
      }
      return Optional.of(new HeaderValue(overrideName, result.get().value()));
    }
  }
}
