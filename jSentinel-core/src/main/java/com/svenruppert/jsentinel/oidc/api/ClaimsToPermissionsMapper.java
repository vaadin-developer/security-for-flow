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
package com.svenruppert.jsentinel.oidc.api;

import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;

import java.util.Optional;
import java.util.Set;

/**
 * Maps OIDC claims to {@link PermissionName}s (V00.78). Default is empty (no
 * permissions); applications supply their own when the IdP carries fine-grained
 * authorization claims.
 *
 * @since 00.78.00
 */
public interface ClaimsToPermissionsMapper {
  Set<PermissionName> mapPermissions(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo);
}
