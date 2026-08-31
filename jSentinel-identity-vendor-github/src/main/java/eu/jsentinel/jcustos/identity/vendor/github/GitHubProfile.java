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
package eu.jsentinel.jcustos.identity.vendor.github;

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.oidc.api.ClaimsToSubjectMapper;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.VendorProfile;

import java.util.Optional;
import java.util.Set;

/**
 * The GitHub vendor profile (V00.79). GitHub speaks OAuth2 but issues no ID token,
 * so identity comes from the UserInfo (the {@code /user} API).
 *
 * <p><strong>JS-SEC-039 (CWE-290):</strong> the subject id is anchored to GitHub's
 * <em>immutable numeric account id</em> ({@code github#<id>}), never the mutable
 * {@code login} (username). A GitHub {@code login} can be renamed at any time and,
 * once relinquished, immediately reclaimed by any other account — keying identity on
 * it would let an attacker who claims a freed username inherit the previous holder's
 * local grants. The numeric id comes from the UserInfo {@code sub} (a correct GitHub
 * UserInfo adapter maps the numeric {@code id} into {@code sub}), falling back to the
 * raw numeric {@code id} claim, then the id_token {@code sub}. The mapper fails closed
 * when no stable numeric id is available rather than silently keying on {@code login}.
 * {@code name} (falling back to {@code login}) is display-only.
 */
public final class GitHubProfile implements VendorProfile {

  public static final GitHubProfile INSTANCE = new GitHubProfile();

  public GitHubProfile() {
  }

  @Override
  public String id() {
    return "github";
  }

  @Override
  public Optional<ClaimsToSubjectMapper> subjectMapper() {
    return Optional.of((idToken, userInfo) -> {
      // JS-SEC-039 (CWE-290): key on the immutable numeric account id, never the mutable
      // `login`. Prefer the UserInfo `sub` (numeric id), then the raw numeric `id` claim
      // (GitHub returns `id` as a JSON number, so read it as Number — claim("id",
      // String.class) would silently return empty and fall back to login again), then the
      // id_token sub. Fail closed if none is present.
      String stableId = userInfo.map(UserInfoResponse::subject).filter(s -> !s.isBlank())
          .or(() -> userInfo.flatMap(u -> u.claim("id", Number.class))
              .map(n -> String.valueOf(n.longValue())))
          .or(idToken::subject)
          .orElseThrow(() -> new IllegalArgumentException(
              "github: no stable numeric account id available (UserInfo sub / id / id_token sub)"));
      Optional<String> login = userInfo.flatMap(u -> u.claim("login", String.class));
      String displayName = userInfo.flatMap(u -> u.claim("name", String.class))
          .or(() -> login)
          .orElse(stableId);
      return new JSentinelSubject("github#" + stableId, displayName, Set.of(), Set.of());
    });
  }
}
