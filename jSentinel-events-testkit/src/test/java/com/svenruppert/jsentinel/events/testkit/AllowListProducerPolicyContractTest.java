package com.svenruppert.jsentinel.events.testkit;

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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventType;
import com.svenruppert.jsentinel.events.producer.AllowListProducerPolicy;
import com.svenruppert.jsentinel.events.producer.JSentinelEventProducerPolicy;

class AllowListProducerPolicyContractTest implements ProducerPolicyContract {
  private static final EventProducerId REST = EventProducerId.of("rest-service-primary");
  private static final EventType LOGIN = EventType.of("LoginSucceeded");
  public JSentinelEventProducerPolicy newPolicy() {
    return AllowListProducerPolicy.builder().allow(REST, LOGIN).build();
  }
  public Allowed allowed() { return new Allowed(REST, LOGIN, TenantId.DEFAULT); }
  public Denied denied() { return new Denied(REST, EventType.of("RoleAssigned"), TenantId.DEFAULT); }
}
