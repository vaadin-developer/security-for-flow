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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;

/**
 * V00.74 sub-builder for token-propagation wiring. Exposed via
 * {@code .propagation(...)} on
 * {@link CommonJCustosBootstrap}; all three adapter facades
 * inherit it for free.
 *
 * <p>Composition rules (Konzept §10):
 * <ul>
 *   <li>{@link #credentialStore(TokenCredentialStore)} overrides the
 *       SPI-discovered adapter default.</li>
 *   <li>{@link #defaultStrategy(OutboundTokenStrategy)} registers the
 *       strategy under the conventional {@code default} alias. May not
 *       be combined with {@link #passThrough()} on the same builder.</li>
 *   <li>{@link #strategy(String, OutboundTokenStrategy)} registers a
 *       named strategy; duplicate names raise.</li>
 *   <li>{@link #passThrough()} — convenience for
 *       {@code defaultStrategy(PassThroughStrategy.INSTANCE)}.</li>
 * </ul>
 *
 * @since 00.74.00
 */
public interface PropagationBootstrap {

  /** Override the SPI-discovered adapter default store. */
  PropagationBootstrap credentialStore(TokenCredentialStore store);

  /** Register the strategy under the {@code default} alias. */
  PropagationBootstrap defaultStrategy(OutboundTokenStrategy strategy);

  /** Register a named strategy. */
  PropagationBootstrap strategy(String name, OutboundTokenStrategy strategy);

  /** Convenience for {@code defaultStrategy(PassThroughStrategy.INSTANCE)}. */
  PropagationBootstrap passThrough();
}
