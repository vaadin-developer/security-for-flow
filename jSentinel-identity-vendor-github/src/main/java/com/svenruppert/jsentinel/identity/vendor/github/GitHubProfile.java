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
package com.svenruppert.jsentinel.identity.vendor.github;

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.oidc.api.ClaimsToSubjectMapper;
import com.svenruppert.jsentinel.oidc.api.VendorProfile;

import java.util.Optional;
import java.util.Set;

/**
 * The GitHub vendor profile (V00.79). GitHub speaks OAuth2 but issues no ID token,
 * so identity comes from the UserInfo (the {@code /user} API): {@code login} is the
 * stable subject, {@code name} (falling back to {@code login}) is the display name.
 * The subject id is prefixed {@code github#<login>} to avoid cross-provider
 * collisions. The ID-token argument is only used as a {@code sub} fallback when no
 * UserInfo is supplied.
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
      Optional<String> login = userInfo.flatMap(u -> u.claim("login", String.class));
      String sub = login.or(idToken::subject).orElseThrow(
          () -> new IllegalArgumentException("github: no login / sub available"));
      String displayName = userInfo.flatMap(u -> u.claim("name", String.class))
          .or(() -> login)
          .orElse(sub);
      return new JSentinelSubject("github#" + sub, displayName, Set.of(), Set.of());
    });
  }
}
