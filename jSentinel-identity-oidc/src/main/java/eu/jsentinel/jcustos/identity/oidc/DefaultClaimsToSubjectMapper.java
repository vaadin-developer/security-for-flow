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
package eu.jsentinel.jcustos.identity.oidc;

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.oidc.api.ClaimsToPermissionsMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToSubjectMapper;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

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
 * ({@link eu.jsentinel.jcustos.oidc.api.ClaimsToTenantMapper}); the OIDC
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
    // R-EXIT-2 / OIDC Core §5.3.2: a UserInfo response MUST be for the same subject
    // as the ID token, otherwise its claims must not be trusted.
    userInfo.ifPresent(ui -> {
      if (!idToken.subject().map(ui.subject()::equals).orElse(false)) {
        throw new IllegalArgumentException(
            "oidc/userinfo-sub-mismatch: UserInfo sub does not match the ID token sub");
      }
    });
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
    // R-EXIT-1: an injective encoding — sub may legally contain '#', so a raw
    // delimiter is ambiguous (iss="a",sub="b#c" vs iss="a#b",sub="c"). Escape '%'
    // then '#' in both components so the '#' join cannot collide.
    return idToken.issuer().map(iss -> escape(iss) + "#" + escape(sub)).orElse(sub);
  }

  private static String escape(String value) {
    return value.replace("%", "%25").replace("#", "%23");
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
