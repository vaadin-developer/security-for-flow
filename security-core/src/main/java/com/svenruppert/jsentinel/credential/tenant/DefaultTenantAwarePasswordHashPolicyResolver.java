/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.jsentinel.credential.tenant;

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.credential.password.policy.PasswordHashPolicy;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * In-memory {@link TenantAwarePasswordHashPolicyResolver} that
 * stores a global default plus optional per-tenant overrides.
 *
 * <p>Look-up rule: an explicit override for the requested
 * {@link TenantId} wins. Unknown tenants — and the single-tenant
 * default — fall back to the constructor-supplied
 * {@code defaultPolicy}. The resolver never throws on lookup; an
 * unknown tenant is not a failure but a normal single-tenant
 * case.</p>
 */
public final class DefaultTenantAwarePasswordHashPolicyResolver
    implements TenantAwarePasswordHashPolicyResolver {

  private final PasswordHashPolicy defaultPolicy;
  private final Map<TenantId, PasswordHashPolicy> overrides;

  public DefaultTenantAwarePasswordHashPolicyResolver(
      PasswordHashPolicy defaultPolicy,
      Map<TenantId, PasswordHashPolicy> overrides) {
    this.defaultPolicy = Objects.requireNonNull(defaultPolicy, "defaultPolicy");
    Objects.requireNonNull(overrides, "overrides");
    this.overrides = Map.copyOf(overrides);
  }

  public DefaultTenantAwarePasswordHashPolicyResolver(
      PasswordHashPolicy defaultPolicy) {
    this(defaultPolicy, new HashMap<>());
  }

  @Override
  public PasswordHashPolicy resolve(TenantCredentialContext context) {
    Objects.requireNonNull(context, "context");
    PasswordHashPolicy explicit = overrides.get(context.tenantId());
    return explicit != null ? explicit : defaultPolicy;
  }

  /** Returns the policy bound to single-tenant fallback. */
  PasswordHashPolicy defaultPolicy() {
    return defaultPolicy;
  }

  int overrideCount() {
    return overrides.size();
  }
}
