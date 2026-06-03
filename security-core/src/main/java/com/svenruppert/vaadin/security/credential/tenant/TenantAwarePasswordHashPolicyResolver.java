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
package com.svenruppert.vaadin.security.credential.tenant;

import com.svenruppert.vaadin.security.credential.password.policy.PasswordHashPolicy;

/**
 * SPI that resolves the {@link PasswordHashPolicy} for a given
 * {@link TenantCredentialContext}.
 *
 * <p>The default deployment binding is single-tenant — see
 * {@link DefaultTenantAwarePasswordHashPolicyResolver}. Multi-tenant
 * deployments register a tenant-aware resolver that switches
 * algorithm / parameters / policyVersion per tenant.</p>
 *
 * <p>The resolver MUST return a non-null policy for every input.
 * Unknown tenants fall back to the operator-configured default —
 * implementations must not throw, otherwise a public failure
 * could leak tenant existence (CWE-203).</p>
 */
@FunctionalInterface
public interface TenantAwarePasswordHashPolicyResolver {

  PasswordHashPolicy resolve(TenantCredentialContext context);
}
