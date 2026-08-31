package eu.jsentinel.jcustos.events.api;

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

/**
 * Technical identity of the component that issued an envelope, e.g.
 * {@code "rest-service-primary"} or {@code "vaadin-client"} (Konzept §678).
 *
 * <p>The producer policy decides which event types a given producer may
 * publish for a given tenant, preventing low-authority consumers from
 * forging high-authority events.
 *
 * @param value non-blank producer identifier
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record EventProducerId(String value) {

  public EventProducerId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("EventProducerId value must not be null or blank");
    }
  }

  public static EventProducerId of(String value) {
    return new EventProducerId(value);
  }
}
