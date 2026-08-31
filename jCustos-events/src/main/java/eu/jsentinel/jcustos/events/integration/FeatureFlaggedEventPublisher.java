package eu.jsentinel.jcustos.events.integration;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.bus.JCustosEventBus;

import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Wraps a {@link JCustosEventBus} and only publishes when bus emission is
 * enabled (Konzept §1029, plan P034). This is the building block existing
 * session / token / rate-limit code paths use to emit their events behind the
 * {@link JCustosEventBusFeatureFlag} without coupling {@code jCustos-core}'s
 * services to the events module: a host wires the publisher and calls
 * {@link #publishIfEnabled(JCustosEvent)} where it formerly only audited.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class FeatureFlaggedEventPublisher {

  private final JCustosEventBus bus;
  private final BooleanSupplier enabled;

  /**
   * Uses the global {@link JCustosEventBusFeatureFlag}.
   *
   * @param bus the event bus
   */
  public FeatureFlaggedEventPublisher(JCustosEventBus bus) {
    this(bus, JCustosEventBusFeatureFlag::enabled);
  }

  /**
   * @param bus the event bus
   * @param enabled the flag supplier (e.g. for tests or per-deployment config)
   */
  public FeatureFlaggedEventPublisher(JCustosEventBus bus, BooleanSupplier enabled) {
    this.bus = Objects.requireNonNull(bus, "bus");
    this.enabled = Objects.requireNonNull(enabled, "enabled");
  }

  /**
   * Publishes the event only when emission is enabled.
   *
   * @param event the event to publish
   * @return {@code true} if it was published, {@code false} if emission is off
   */
  public boolean publishIfEnabled(JCustosEvent event) {
    Objects.requireNonNull(event, "event");
    if (!enabled.getAsBoolean()) {
      return false;
    }
    bus.publish(event);
    return true;
  }
}
