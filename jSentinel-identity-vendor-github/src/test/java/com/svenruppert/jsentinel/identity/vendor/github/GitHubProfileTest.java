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
  @DisplayName("builds the subject from the GitHub login + name in UserInfo")
  void buildsSubjectFromUserInfo() {
    UserInfoResponse userInfo = new UserInfoResponse("12345",
        Map.of("sub", "12345", "login", "octocat", "name", "The Octocat"));
    JSentinelSubject subject = GitHubProfile.INSTANCE.subjectMapper().orElseThrow()
        .map(placeholderIdToken(), Optional.of(userInfo));
    assertEquals("github#octocat", subject.subjectId());
    assertEquals("The Octocat", subject.displayName());
    assertEquals("github", GitHubProfile.INSTANCE.id());
  }
}
