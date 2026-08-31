package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jSentinel Events — Contract testkit
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
import eu.jsentinel.jcustos.events.producer.JSentinelEventProducerPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JSentinelEventProducerPolicy} implementations.
 * The implementer supplies a policy plus the {@code (producer, eventType,
 * tenant)} triples it allows and denies.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
@DisplayName("JSentinelEventProducerPolicy — contract")
public interface ProducerPolicyContract {

  /** @return the policy under test. */
  JSentinelEventProducerPolicy newPolicy();

  /** @return a triple the policy must allow. */
  Allowed allowed();

  /** @return a triple the policy must deny. */
  Denied denied();

  /** An allowed {@code (producer, eventType, tenant)} triple. */
  record Allowed(EventProducerId producerId, EventType eventType, TenantId tenantId) {
  }

  /** A denied {@code (producer, eventType, tenant)} triple. */
  record Denied(EventProducerId producerId, EventType eventType, TenantId tenantId) {
  }

  @Test
  @DisplayName("an allowed producer/type/tenant triple may publish")
  default void allowedMayPublish() {
    Allowed a = allowed();
    assertTrue(newPolicy().mayPublish(a.producerId(), a.eventType(), a.tenantId()));
  }

  @Test
  @DisplayName("a denied producer/type/tenant triple may not publish")
  default void deniedMayNotPublish() {
    Denied d = denied();
    assertFalse(newPolicy().mayPublish(d.producerId(), d.eventType(), d.tenantId()));
  }
}
