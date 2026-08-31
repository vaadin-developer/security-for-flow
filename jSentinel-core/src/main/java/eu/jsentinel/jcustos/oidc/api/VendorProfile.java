/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.oidc.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.Optional;

/**
 * A vendor-specific bundle of OIDC claim mappers (V00.79). Real IdPs diverge from
 * the spec on where they put roles / groups / tenant — Keycloak uses
 * {@code realm_access.roles}, Entra uses {@code wids}/{@code roles}/{@code groups},
 * Auth0 uses a namespaced custom claim. A {@code VendorProfile} packages the
 * matching {@link ClaimsToRolesMapper} / {@link ClaimsToPermissionsMapper} /
 * {@link ClaimsToTenantMapper} / {@link ClaimsToSubjectMapper} so a consumer wires
 * one object — {@code .oidc(o -> o.vendor(KeycloakProfile.INSTANCE))} — instead of
 * each mapper individually. Each override is optional; an empty {@link Optional}
 * means "keep the spec-clean default". The concrete profiles live in the opt-in
 * {@code jSentinel-identity-vendor-*} modules.
 *
 * @since 00.79.00
 */
@ExperimentalJSentinelApi
public interface VendorProfile {

  /** @return a stable vendor id (e.g. {@code "keycloak"}, {@code "entra"}). */
  String id();

  /** @return the vendor roles mapper, if the profile overrides role extraction. */
  default Optional<ClaimsToRolesMapper> rolesMapper() {
    return Optional.empty();
  }

  /** @return the vendor permissions mapper, if any. */
  default Optional<ClaimsToPermissionsMapper> permissionsMapper() {
    return Optional.empty();
  }

  /** @return the vendor tenant mapper, if any. */
  default Optional<ClaimsToTenantMapper> tenantMapper() {
    return Optional.empty();
  }

  /** @return a fully custom subject mapper, if the vendor needs more than role/tenant overrides. */
  default Optional<ClaimsToSubjectMapper> subjectMapper() {
    return Optional.empty();
  }
}
