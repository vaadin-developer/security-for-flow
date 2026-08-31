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

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.jwt.api.JoseHeader;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DefaultClaimsToSubjectMapper — 4-field subject, issuer-prefixed id, displayName fallback")
class DefaultClaimsToSubjectMapperTest {

  private static final String ISS = "https://idp.example/";

  private static ValidatedIdToken idToken(Map<String, Object> extraClaims) {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("iss", ISS);
    claims.put("sub", "alice");
    claims.putAll(extraClaims);
    ValidatedJwt jwt = new ValidatedJwt("compact",
        new JoseHeader("RS256", Optional.empty(), Optional.empty()), claims, Instant.now());
    return new ValidatedIdToken(jwt, Optional.empty(), Optional.empty(), Optional.empty(),
        List.of(), Optional.empty(), Optional.empty());
  }

  @Test
  @DisplayName("subject id is issuer-prefixed (iss#sub); name claim wins for displayName")
  void issuerPrefixedWithName() {
    JCustosSubject s = new DefaultClaimsToSubjectMapper()
        .map(idToken(Map.of("name", "Alice Smith")), Optional.empty());
    assertEquals(ISS + "#alice", s.subjectId());
    assertEquals("Alice Smith", s.displayName());
    assertTrue(s.roles().isEmpty());
    assertTrue(s.permissions().isEmpty());
  }

  @Test
  @DisplayName("displayName falls back name -> preferred_username -> email -> sub")
  void displayNameFallback() {
    assertEquals("bob_pu", new DefaultClaimsToSubjectMapper()
        .map(idToken(Map.of("preferred_username", "bob_pu")), Optional.empty()).displayName());
    assertEquals("c@example.com", new DefaultClaimsToSubjectMapper()
        .map(idToken(Map.of("email", "c@example.com")), Optional.empty()).displayName());
    assertEquals("alice", new DefaultClaimsToSubjectMapper()
        .map(idToken(Map.of()), Optional.empty()).displayName());
  }

  @Test
  @DisplayName("UserInfo supplies displayName claims the ID token lacks")
  void userInfoSuppliesDisplayName() {
    UserInfoResponse ui = new UserInfoResponse("alice", Map.of("sub", "alice", "name", "Alice From UserInfo"));
    JCustosSubject s = new DefaultClaimsToSubjectMapper().map(idToken(Map.of()), Optional.of(ui));
    assertEquals("Alice From UserInfo", s.displayName());
  }

  @Test
  @DisplayName("the non-issuer-prefixed mode uses the bare sub")
  void bareSubMode() {
    JCustosSubject s = new DefaultClaimsToSubjectMapper(
        EmptyRolesMapper.INSTANCE, EmptyPermissionsMapper.INSTANCE, false)
        .map(idToken(Map.of("name", "Alice")), Optional.empty());
    assertEquals("alice", s.subjectId());
  }

  @Test
  @DisplayName("R-EXIT-2: a UserInfo sub differing from the ID token sub is rejected (§5.3.2)")
  void userInfoSubMismatchRejected() {
    UserInfoResponse ui = new UserInfoResponse("someone-else", Map.of("sub", "someone-else"));
    org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
        () -> new DefaultClaimsToSubjectMapper().map(idToken(Map.of()), Optional.of(ui)));
  }

  @Test
  @DisplayName("R-EXIT-1: the issuer-prefixed subject id is injective when sub contains '#'")
  void injectiveSubjectId() {
    DefaultClaimsToSubjectMapper mapper = new DefaultClaimsToSubjectMapper();
    String a = mapper.map(idTokenWith("https://a", "b#c"), Optional.empty()).subjectId();
    String b = mapper.map(idTokenWith("https://a#b", "c"), Optional.empty()).subjectId();
    org.junit.jupiter.api.Assertions.assertNotEquals(a, b,
        "distinct (iss,sub) pairs must not collide on the subject id");
  }

  private static ValidatedIdToken idTokenWith(String iss, String sub) {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("iss", iss);
    claims.put("sub", sub);
    eu.jsentinel.jcustos.jwt.api.ValidatedJwt jwt =
        new eu.jsentinel.jcustos.jwt.api.ValidatedJwt("c",
            new eu.jsentinel.jcustos.jwt.api.JoseHeader("RS256", Optional.empty(), Optional.empty()),
            claims, Instant.now());
    return new ValidatedIdToken(jwt, Optional.empty(), Optional.empty(),
        Optional.empty(), List.of(), Optional.empty(), Optional.empty());
  }
}
