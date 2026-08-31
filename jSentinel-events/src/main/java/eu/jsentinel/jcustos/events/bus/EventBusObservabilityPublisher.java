package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.types.EventBusSelfObservabilityEvent;

/**
 * Emission point for {@link EventBusSelfObservabilityEvent}s.
 *
 * <p>Contract: {@link #publishObservability(EventBusSelfObservabilityEvent)}
 * never throws. Implementations treat every emission failure as log-only, and
 * callers rely on that — an observability emission must never mask or replace
 * the primary outcome it reports about. Implementations dispatch directly to
 * listeners and never route through the signed publish pipeline (see
 * {@link EventBusSelfObservabilityEvent} for why).
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
@FunctionalInterface
public interface EventBusObservabilityPublisher {

  /**
   * Emits a bus self-observability event. Never throws; failures are
   * handled log-only by the implementation.
   *
   * @param event the non-null event to emit
   */
  void publishObservability(EventBusSelfObservabilityEvent event);

  /**
   * @return a publisher that silently discards every event
   */
  static EventBusObservabilityPublisher discard() {
    return event -> {
    };
  }
}
