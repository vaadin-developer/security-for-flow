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
package com.svenruppert.jsentinel.identity.oidc;

/*-
 * #%L
 * jSentinel OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.oidc.api.ClaimsToPermissionsMapper;
import com.svenruppert.jsentinel.oidc.api.ClaimsToRolesMapper;
import com.svenruppert.jsentinel.oidc.api.ClaimsToSubjectMapper;
import com.svenruppert.jsentinel.oidc.api.UserInfoResponse;
import com.svenruppert.jsentinel.oidc.api.ValidatedIdToken;

import java.util.Objects;
import java.util.Optional;

/**
 * The spec-clean default {@link ClaimsToSubjectMapper} (V00.78). Builds the
 * 4-field stable {@link JSentinelSubject}: an issuer-prefixed subject id
 * ({@code iss + "#" + sub} — defeats cross-IdP subject collisions), a display name
 * from the standard claims ({@code name} → {@code preferred_username} →
 * {@code email} → {@code sub}), and roles / permissions from the injected
 * {@link ClaimsToRolesMapper} / {@link ClaimsToPermissionsMapper} (empty by
 * default). Tenant assignment is a separate concern
 * ({@link com.svenruppert.jsentinel.oidc.api.ClaimsToTenantMapper}); the OIDC
 * context claims stay on the {@link ValidatedIdToken}. Vendor role/claim mappings
 * are a V00.79 concern.
 */
public final class DefaultClaimsToSubjectMapper implements ClaimsToSubjectMapper {

  private final ClaimsToRolesMapper rolesMapper;
  private final ClaimsToPermissionsMapper permissionsMapper;
  private final boolean issuerPrefixed;

  /** Default: issuer-prefixed ids, empty roles + permissions. */
  public DefaultClaimsToSubjectMapper() {
    this(EmptyRolesMapper.INSTANCE, EmptyPermissionsMapper.INSTANCE, true);
  }

  public DefaultClaimsToSubjectMapper(ClaimsToRolesMapper rolesMapper,
      ClaimsToPermissionsMapper permissionsMapper) {
    this(rolesMapper, permissionsMapper, true);
  }

  public DefaultClaimsToSubjectMapper(ClaimsToRolesMapper rolesMapper,
      ClaimsToPermissionsMapper permissionsMapper, boolean issuerPrefixed) {
    this.rolesMapper = Objects.requireNonNull(rolesMapper, "rolesMapper");
    this.permissionsMapper = Objects.requireNonNull(permissionsMapper, "permissionsMapper");
    this.issuerPrefixed = issuerPrefixed;
  }

  @Override
  public JSentinelSubject map(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
    Objects.requireNonNull(idToken, "idToken");
    Objects.requireNonNull(userInfo, "userInfo");
    return new JSentinelSubject(
        buildSubjectId(idToken),
        displayName(idToken, userInfo),
        rolesMapper.mapRoles(idToken, userInfo),
        permissionsMapper.mapPermissions(idToken, userInfo));
  }

  private String buildSubjectId(ValidatedIdToken idToken) {
    String sub = idToken.subject().orElseThrow(
        () -> new IllegalArgumentException("id token without sub"));
    if (!issuerPrefixed) {
      return sub;
    }
    return idToken.issuer().map(iss -> iss + "#" + sub).orElse(sub);
  }

  private static String displayName(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
    return firstClaim(idToken, userInfo, "name")
        .or(() -> firstClaim(idToken, userInfo, "preferred_username"))
        .or(() -> firstClaim(idToken, userInfo, "email"))
        .or(idToken::subject)
        .orElse("unknown");
  }

  private static Optional<String> firstClaim(ValidatedIdToken idToken,
      Optional<UserInfoResponse> userInfo, String claim) {
    return idToken.jwt().claim(claim, String.class)
        .or(() -> userInfo.flatMap(u -> u.claim(claim, String.class)));
  }
}
