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
package com.svenruppert.jsentinel.identity.vendor.google;

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.oidc.api.ClaimsToTenantMapper;
import com.svenruppert.jsentinel.oidc.api.VendorProfile;

import java.util.Optional;

/**
 * The Google vendor profile (V00.79). Google does not emit roles, but Workspace
 * tokens carry the hosted-domain {@code hd} claim, mapped here to the tenant — the
 * natural multi-tenant boundary for Workspace logins. (Google's other quirks —
 * mandatory PKCE for confidential clients, a missing {@code at_hash} on some v1
 * endpoints, strict {@code email_verified} — are configuration concerns documented
 * for the consumer, not claim mappings.)
 */
public final class GoogleProfile implements VendorProfile {

  public static final GoogleProfile INSTANCE = new GoogleProfile();

  public GoogleProfile() {
  }

  @Override
  public String id() {
    return "google";
  }

  @Override
  public Optional<ClaimsToTenantMapper> tenantMapper() {
    return Optional.of((idToken, userInfo) ->
        idToken.jwt().claim("hd", String.class).map(TenantId::of));
  }
}
