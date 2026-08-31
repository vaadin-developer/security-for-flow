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

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;

import java.util.Optional;

/**
 * Maps validated OIDC claims to a {@link JCustosSubject} (V00.78). The default
 * implementation ({@code jCustos-identity-oidc}) builds the 4-field stable
 * subject — issuer-prefixed subject id, a display name from the standard claims,
 * and the roles / permissions from the dedicated {@link ClaimsToRolesMapper} /
 * {@link ClaimsToPermissionsMapper}. Tenant assignment (where applicable) is a
 * separate concern handled by {@link ClaimsToTenantMapper}; OIDC context claims
 * ({@code acr}/{@code amr}/{@code auth_time}/{@code email}/…) stay on the
 * {@link ValidatedIdToken} for the step-up evaluator rather than being folded into
 * the stable subject record.
 *
 * @since 00.78.00
 */
public interface ClaimsToSubjectMapper {

  /**
   * Builds a subject from the validated ID token and optional UserInfo claims.
   *
   * @param idToken  the validated ID token
   * @param userInfo the UserInfo claims, if pulled
   * @return the mapped subject (id / displayName / roles / permissions)
   */
  JCustosSubject map(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo);
}
