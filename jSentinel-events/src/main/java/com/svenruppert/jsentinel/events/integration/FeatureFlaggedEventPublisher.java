package com.svenruppert.jsentinel.events.integration;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.bus.JSentinelEventBus;

import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Wraps a {@link JSentinelEventBus} and only publishes when bus emission is
 * enabled (Konzept §1029, plan P034). This is the building block existing
 * session / token / rate-limit code paths use to emit their events behind the
 * {@link JSentinelEventBusFeatureFlag} without coupling {@code jSentinel-core}'s
 * services to the events module: a host wires the publisher and calls
 * {@link #publishIfEnabled(JSentinelEvent)} where it formerly only audited.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class FeatureFlaggedEventPublisher {

  private final JSentinelEventBus bus;
  private final BooleanSupplier enabled;

  /**
   * Uses the global {@link JSentinelEventBusFeatureFlag}.
   *
   * @param bus the event bus
   */
  public FeatureFlaggedEventPublisher(JSentinelEventBus bus) {
    this(bus, JSentinelEventBusFeatureFlag::enabled);
  }

  /**
   * @param bus the event bus
   * @param enabled the flag supplier (e.g. for tests or per-deployment config)
   */
  public FeatureFlaggedEventPublisher(JSentinelEventBus bus, BooleanSupplier enabled) {
    this.bus = Objects.requireNonNull(bus, "bus");
    this.enabled = Objects.requireNonNull(enabled, "enabled");
  }

  /**
   * Publishes the event only when emission is enabled.
   *
   * @param event the event to publish
   * @return {@code true} if it was published, {@code false} if emission is off
   */
  public boolean publishIfEnabled(JSentinelEvent event) {
    Objects.requireNonNull(event, "event");
    if (!enabled.getAsBoolean()) {
      return false;
    }
    bus.publish(event);
    return true;
  }
}
