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

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;

import java.util.Objects;

/**
 * Tenant scope of an in-flight credential operation.
 *
 * <p>Single-tenant deployments never need to construct this
 * explicitly — the framework supplies
 * {@link #SINGLE_TENANT_DEFAULT} when no tenant is resolved.
 * Multi-tenant deployments resolve the {@link TenantId} from the
 * inbound request (subdomain, header, authenticated subject) and
 * pass it through.</p>
 *
 * <p>The context carries the {@code tenantId} only; it deliberately
 * does <em>not</em> embed the candidate username, the email
 * address, or any other personally identifying value. Tenant
 * routing decisions live at this scope; subject routing decisions
 * live in {@code AccessContext} / {@code PasswordContext}.</p>
 *
 * <p>Public failure surfaces must never reveal whether a given
 * tenant exists (CWE-203, CWE-209). The framework guarantees that
 * the {@link TenantId} is not formatted into
 * {@code CompromisedPasswordResult}, {@code AbuseDecision},
 * {@code CredentialVerificationResult} or any other adapter-neutral
 * verdict.</p>
 */
public record TenantCredentialContext(TenantId tenantId) {

  /**
   * Default value for tenant-unaware code paths and single-tenant
   * deployments.
   */
  public static final TenantCredentialContext SINGLE_TENANT_DEFAULT =
      new TenantCredentialContext(TenantId.DEFAULT);

  public TenantCredentialContext {
    Objects.requireNonNull(tenantId, "tenantId");
  }

  /**
   * Convenience factory.
   */
  public static TenantCredentialContext of(TenantId tenantId) {
    return new TenantCredentialContext(tenantId);
  }
}
