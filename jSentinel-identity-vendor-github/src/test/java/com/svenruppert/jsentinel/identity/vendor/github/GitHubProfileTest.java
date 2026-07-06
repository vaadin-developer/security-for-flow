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

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.jwt.api.JoseHeader;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;
import com.svenruppert.jsentinel.oidc.api.UserInfoResponse;
import com.svenruppert.jsentinel.oidc.api.ValidatedIdToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("GitHubProfile — UserInfo-only subject (no ID token)")
class GitHubProfileTest {

  private static ValidatedIdToken placeholderIdToken() {
    return new ValidatedIdToken(new ValidatedJwt("c",
        new JoseHeader("RS256", Optional.empty(), Optional.empty()),
        Map.of("sub", "12345"), Instant.now()),
        Optional.empty(), Optional.empty(), Optional.empty(), List.of(), Optional.empty(),
        Optional.empty());
  }

  @Test
  @DisplayName("JS-SEC-039: anchors the subject to the immutable numeric id (sub), login is display-only")
  void anchorsSubjectToNumericIdNotLogin() {
    UserInfoResponse userInfo = new UserInfoResponse("12345",
        Map.of("sub", "12345", "login", "octocat", "name", "The Octocat"));
    JSentinelSubject subject = GitHubProfile.INSTANCE.subjectMapper().orElseThrow()
        .map(placeholderIdToken(), Optional.of(userInfo));
    // the principal keys on the numeric id, NOT the reclaimable login "octocat"
    assertEquals("github#12345", subject.subjectId());
    assertEquals("The Octocat", subject.displayName());
    assertEquals("github", GitHubProfile.INSTANCE.id());
  }

  @Test
  @DisplayName("JS-SEC-039: falls back to the raw numeric `id` claim when `sub` is blank")
  void fallsBackToNumericIdClaim() {
    // a GitHub UserInfo whose `sub` was not populated but which carries the numeric `id`
    // as a JSON number — must still key on the id, not the login.
    UserInfoResponse userInfo = new UserInfoResponse("",
        Map.of("id", 12345, "login", "octocat"));
    JSentinelSubject subject = GitHubProfile.INSTANCE.subjectMapper().orElseThrow()
        .map(placeholderIdToken(), Optional.of(userInfo));
    assertEquals("github#12345", subject.subjectId());
    assertEquals("octocat", subject.displayName());
  }
}
