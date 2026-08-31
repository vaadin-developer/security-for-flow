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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.util.Optional;

/**
 * Maps OIDC claims to a {@link TenantId} (V00.78). Because the stable
 * {@link eu.jsentinel.jcustos.authorization.api.JCustosSubject} carries no
 * tenant field, tenant assignment is a dedicated concern: the default returns
 * empty; multi-tenant applications derive the tenant from an IdP claim
 * (organization, realm, …).
 *
 * @since 00.78.00
 */
public interface ClaimsToTenantMapper {
  Optional<TenantId> mapTenant(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo);
}
