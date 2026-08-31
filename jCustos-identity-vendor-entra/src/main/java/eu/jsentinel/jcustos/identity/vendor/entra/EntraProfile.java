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
package eu.jsentinel.jcustos.identity.vendor.entra;

import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToTenantMapper;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;
import eu.jsentinel.jcustos.oidc.api.VendorProfile;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The Entra ID (Azure AD) vendor profile (V00.79). Entra emits app roles in
 * {@code roles}, directory roles in {@code wids} and group memberships in
 * {@code groups} (depending on app configuration) — all combined into roles here.
 * The tenant is the {@code tid} claim. Reads only the signed ID-token claims.
 */
public final class EntraProfile implements VendorProfile {

  public static final EntraProfile INSTANCE = new EntraProfile();

  public EntraProfile() {
  }

  @Override
  public String id() {
    return "entra";
  }

  @Override
  public Optional<ClaimsToRolesMapper> rolesMapper() {
    return Optional.of(new RolesMapper());
  }

  @Override
  public Optional<ClaimsToTenantMapper> tenantMapper() {
    return Optional.of(new TenantMapper());
  }

  /** Combines {@code roles} + {@code wids} + {@code groups} string arrays into roles. */
  public static final class RolesMapper implements ClaimsToRolesMapper {
    @Override
    public Set<RoleName> mapRoles(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
      Map<String, Object> claims = idToken.jwt().claims();
      Set<RoleName> roles = new LinkedHashSet<>();
      addStrings(claims.get("roles"), roles);
      addStrings(claims.get("wids"), roles);
      addStrings(claims.get("groups"), roles);
      return roles;
    }

    private static void addStrings(Object value, Set<RoleName> roles) {
      if (value instanceof List<?> list) {
        for (Object o : list) {
          if (o instanceof String s) {
            roles.add(new RoleName(s));
          }
        }
      }
    }
  }

  /** Maps the Entra {@code tid} claim to a {@link TenantId}. */
  public static final class TenantMapper implements ClaimsToTenantMapper {
    @Override
    public Optional<TenantId> mapTenant(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
      return idToken.jwt().claim("tid", String.class).map(TenantId::of);
    }
  }
}
