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
package com.svenruppert.jsentinel.identity.vendor.okta;

import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.oidc.api.ClaimsToRolesMapper;
import com.svenruppert.jsentinel.oidc.api.VendorProfile;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The Okta vendor profile (V00.79). Okta delivers group memberships in the
 * {@code groups} claim (when the authorization server is configured to include it),
 * mapped here to roles. Reads only the signed ID-token claims.
 */
public final class OktaProfile implements VendorProfile {

  public static final OktaProfile INSTANCE = new OktaProfile();

  public OktaProfile() {
  }

  @Override
  public String id() {
    return "okta";
  }

  @Override
  public Optional<ClaimsToRolesMapper> rolesMapper() {
    return Optional.of((idToken, userInfo) -> {
      Set<RoleName> roles = new LinkedHashSet<>();
      if (idToken.jwt().claims().get("groups") instanceof List<?> list) {
        for (Object o : list) {
          if (o instanceof String s) {
            roles.add(new RoleName(s));
          }
        }
      }
      return roles;
    });
  }
}
