/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.tenant;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.credential.password.pepper.PepperReference;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * In-memory {@link TenantAwarePepperReferenceResolver}.
 *
 * <p>Carries an optional global default and a per-tenant
 * override map. Unknown tenants fall back to the default; the
 * default may itself be empty, in which case verification
 * proceeds without a pepper application.</p>
 */
public final class DefaultTenantAwarePepperReferenceResolver
    implements TenantAwarePepperReferenceResolver {

  private final Optional<PepperReference> defaultReference;
  private final Map<TenantId, PepperReference> overrides;

  public DefaultTenantAwarePepperReferenceResolver(
      Optional<PepperReference> defaultReference,
      Map<TenantId, PepperReference> overrides) {
    this.defaultReference = Objects.requireNonNull(
        defaultReference, "defaultReference");
    Objects.requireNonNull(overrides, "overrides");
    this.overrides = Map.copyOf(overrides);
  }

  /**
   * Single-tenant convenience: every tenant resolves to the same
   * (possibly empty) reference.
   */
  public static DefaultTenantAwarePepperReferenceResolver singleTenant(
      Optional<PepperReference> reference) {
    return new DefaultTenantAwarePepperReferenceResolver(
        reference, new HashMap<>());
  }

  @Override
  public Optional<PepperReference> activeReferenceFor(
      TenantCredentialContext context) {
    Objects.requireNonNull(context, "context");
    PepperReference explicit = overrides.get(context.tenantId());
    return explicit != null
        ? Optional.of(explicit)
        : defaultReference;
  }

  int overrideCount() {
    return overrides.size();
  }
}
