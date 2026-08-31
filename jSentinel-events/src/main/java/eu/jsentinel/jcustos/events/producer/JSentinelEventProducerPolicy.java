package eu.jsentinel.jcustos.events.producer;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventType;

/**
 * Producer policy SPI (Konzept §683): decides whether a given producer may
 * publish a given event type for a given tenant. Prevents a low-authority
 * consumer or UI process from forging high-authority events (Konzept §698).
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public interface JSentinelEventProducerPolicy {

  /**
   * @param producerId the issuing producer
   * @param eventType the event type being published
   * @param tenantId the tenant context
   * @return {@code true} if the producer is allowed to publish this event type
   *     for this tenant
   */
  boolean mayPublish(EventProducerId producerId, EventType eventType, TenantId tenantId);
}
