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

import com.svenruppert.vaadin.security.credential.password.pepper.PepperReference;

import java.util.Optional;

/**
 * SPI that resolves the active {@link PepperReference} for a
 * tenant context.
 *
 * <p>Returning {@link Optional#empty()} means "no pepper for this
 * tenant" — the credential pipeline proceeds without a pepper
 * application; this is the default for single-tenant deployments
 * that have opted out of pepper.</p>
 *
 * <p>An implementation backed by a PKCS#11 / HSM resolves the
 * tenant to a key handle internally and returns a
 * {@link PepperReference} that wraps only the {@code keyId}
 * (with empty key bytes), so the hot pepper key material never
 * leaves the secure element — see
 * {@code docs/security/credentials/standards/pkcs11-hsm-pepper-key.md}.</p>
 *
 * <p>The resolver must not throw on unknown tenants; an unknown
 * tenant simply has no pepper binding (single-tenant fallback).</p>
 */
@FunctionalInterface
public interface TenantAwarePepperReferenceResolver {

  Optional<PepperReference> activeReferenceFor(
      TenantCredentialContext context);
}
