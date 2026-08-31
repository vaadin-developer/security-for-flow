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
package eu.jsentinel.jcustos.oauth2.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("oauth2/api — value types (PKCE S256, masking, error codes)")
class OAuth2ApiTest {

  @Test
  @DisplayName("PKCE: generate() yields a 43-char verifier and an S256 challenge = BASE64URL(SHA-256(verifier))")
  void pkceS256() throws Exception {
    PkceVerifier verifier = PkceVerifier.generate();
    assertEquals(43, verifier.value().length(), "32 random bytes base64url-encode to 43 chars");

    PkceChallenge challenge = verifier.challenge();
    assertEquals("S256", challenge.method());

    byte[] expected = MessageDigest.getInstance("SHA-256")
        .digest(verifier.value().getBytes(StandardCharsets.US_ASCII));
    String expectedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(expected);
    assertEquals(expectedChallenge, challenge.codeChallenge());
  }

  @Test
  @DisplayName("PKCE: two generated verifiers differ; toString masks the value")
  void pkceUniqueAndMasked() {
    assertNotEquals(PkceVerifier.generate().value(), PkceVerifier.generate().value());
    assertFalse(PkceVerifier.generate().toString().contains(PkceVerifier.generate().value()));
    assertTrue(PkceVerifier.generate().toString().contains("***"));
  }

  @Test
  @DisplayName("PKCE: plain is rejected; out-of-range verifiers are rejected")
  void pkceGuards() {
    assertThrows(IllegalArgumentException.class, () -> new PkceChallenge("abc", "plain"));
    assertThrows(IllegalArgumentException.class, () -> PkceVerifier.of("too-short"));
  }

  @Test
  @DisplayName("TokenResponse.toString masks access/refresh/id tokens")
  void tokenResponseMasking() {
    TokenResponse tr = new TokenResponse(
        "AT-secret", Optional.of("RT-secret"), Optional.of("ID-secret"),
        "Bearer", Optional.of(Instant.parse("2026-06-26T12:00:00Z")), Set.of("openid"));
    String s = tr.toString();
    assertFalse(s.contains("AT-secret"));
    assertFalse(s.contains("RT-secret"));
    assertFalse(s.contains("ID-secret"));
    assertTrue(s.contains("Bearer"));
    assertTrue(s.contains("openid"));
  }

  @Test
  @DisplayName("OAuth2Error codes are stable and never echo error_description verbatim")
  void errorCodes() {
    assertEquals("oauth2/protocol-error:invalid_grant",
        new OAuth2Error.ProtocolError("invalid_grant").code());
    assertEquals("oauth2/refresh-token-family-revoked",
        new OAuth2Error.RefreshTokenFamilyRevoked().code());
    assertEquals("oauth2/endpoint-error", new OAuth2Error.EndpointError(503).code());
    assertTrue(new OAuth2Error.EndpointError(503).message().contains("503"));
    // a malformed-response message must not echo the raw body detail
    assertFalse(new OAuth2Error.MalformedResponse("super-secret-body").message().contains("super-secret-body"));
  }
}
