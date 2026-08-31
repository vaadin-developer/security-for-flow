package eu.jsentinel.jcustos.events.producer;

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
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventType;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Default allow-list {@link JCustosEventProducerPolicy} (Konzept §683):
 * default-deny, with explicit grants per {@code (producer, eventType)} either
 * for all tenants or scoped to a specific tenant.
 *
 * <p>Build with the fluent {@link Builder}:
 * <pre>{@code
 * var policy = AllowListProducerPolicy.builder()
 *     .allow(restPrimary, LoginSucceededEvent.TYPE)
 *     .allow(restPrimary, RoleAssignedEvent.TYPE)
 *     .allowForTenant(vaadinClient, UiAccessDeniedEvent.TYPE, acme)
 *     .build();
 * }</pre>
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class AllowListProducerPolicy implements JCustosEventProducerPolicy {

  private record AnyTenantGrant(EventProducerId producerId, EventType eventType) {
  }

  private record TenantGrant(EventProducerId producerId, EventType eventType, TenantId tenantId) {
  }

  private final Set<AnyTenantGrant> anyTenant;
  private final Set<TenantGrant> perTenant;

  private AllowListProducerPolicy(Set<AnyTenantGrant> anyTenant, Set<TenantGrant> perTenant) {
    this.anyTenant = anyTenant;
    this.perTenant = perTenant;
  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public boolean mayPublish(EventProducerId producerId, EventType eventType, TenantId tenantId) {
    Objects.requireNonNull(producerId, "producerId");
    Objects.requireNonNull(eventType, "eventType");
    Objects.requireNonNull(tenantId, "tenantId");
    if (anyTenant.contains(new AnyTenantGrant(producerId, eventType))) {
      return true;
    }
    return perTenant.contains(new TenantGrant(producerId, eventType, tenantId));
  }

  /** Fluent builder for {@link AllowListProducerPolicy}. */
  @ExperimentalJCustosApi
  public static final class Builder {
    private final Set<AnyTenantGrant> anyTenant = new HashSet<>();
    private final Set<TenantGrant> perTenant = new HashSet<>();

    private Builder() {
    }

    /**
     * Grants a producer the right to publish an event type for every tenant.
     */
    public Builder allow(EventProducerId producerId, EventType eventType) {
      anyTenant.add(new AnyTenantGrant(
          Objects.requireNonNull(producerId, "producerId"),
          Objects.requireNonNull(eventType, "eventType")));
      return this;
    }

    /**
     * Grants a producer the right to publish an event type only for a specific
     * tenant.
     */
    public Builder allowForTenant(EventProducerId producerId, EventType eventType,
        TenantId tenantId) {
      perTenant.add(new TenantGrant(
          Objects.requireNonNull(producerId, "producerId"),
          Objects.requireNonNull(eventType, "eventType"),
          Objects.requireNonNull(tenantId, "tenantId")));
      return this;
    }

    public AllowListProducerPolicy build() {
      return new AllowListProducerPolicy(Set.copyOf(anyTenant), Set.copyOf(perTenant));
    }
  }
}
