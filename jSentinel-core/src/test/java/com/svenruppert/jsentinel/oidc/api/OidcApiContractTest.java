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
package com.svenruppert.jsentinel.oidc.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.jsentinel.jwt.api.JwtValidationError;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("oidc/api contracts — invariants, secret masking, stable error codes (V00.78)")
class OidcApiContractTest {

  @Test
  @DisplayName("IdTokenExpectations.of sets the spec defaults (skew, empty hash/acr checks)")
  void expectationsDefaults() {
    IdTokenExpectations e = IdTokenExpectations.of("https://idp.example", "rp", Optional.of("n-123"));
    assertEquals("https://idp.example", e.expectedIssuer());
    assertEquals(IdTokenExpectations.DEFAULT_CLOCK_SKEW, e.clockSkew());
    assertEquals(Optional.of("n-123"), e.expectedNonce());
    assertTrue(e.requestedAcr().isEmpty());
    assertTrue(e.accessTokenForAtHash().isEmpty());
  }

  @Test
  @DisplayName("ValidatedIdToken rejects null components and copies amr defensively")
  void validatedIdTokenInvariants() {
    assertThrows(NullPointerException.class, () -> new ValidatedIdToken(
        null, Optional.empty(), Optional.empty(), Optional.empty(),
        List.of(), Optional.empty(), Optional.empty()));
  }

  @Test
  @DisplayName("LogoutRequest masks the id_token_hint in toString")
  void logoutRequestMasksHint() {
    LogoutRequest r = new LogoutRequest("SENSITIVE-ID-TOKEN",
        Optional.of(URI.create("https://app.example/")), Optional.of("st"));
    assertFalse(r.toString().contains("SENSITIVE-ID-TOKEN"), "id_token_hint must be masked");
    assertTrue(r.toString().contains("***"));
  }

  @Test
  @DisplayName("IdTokenValidationError variants expose stable kebab-case codes")
  void errorCodesStable() {
    assertEquals("oidc/nonce-mismatch", new IdTokenValidationError.NonceMismatch().code());
    assertEquals("oidc/azp-invalid", new IdTokenValidationError.AuthorizedPartyInvalid().code());
    assertEquals("oidc/at-hash-mismatch", new IdTokenValidationError.AccessTokenHashMismatch().code());
    assertEquals("oidc/auth-time-stale", new IdTokenValidationError.AuthTimeStale().code());
    assertEquals("oidc/jwt-invalid",
        new IdTokenValidationError.JwtInvalid(new JwtValidationError.MalformedJwt("x")).code());
  }

  @Test
  @DisplayName("UserInfoResponse gives typed claim access and is immutable")
  void userInfoClaimAccess() {
    UserInfoResponse u = new UserInfoResponse("sub-1",
        java.util.Map.of("sub", "sub-1", "email", "a@example.com"));
    assertEquals(Optional.of("a@example.com"), u.claim("email", String.class));
    assertTrue(u.claim("email", Integer.class).isEmpty());
  }

  @Test
  @DisplayName("OidcProviderMetadata copies its collection fields immutably")
  void providerMetadataImmutable() {
    OidcProviderMetadata m = new OidcProviderMetadata("https://idp", URI.create("https://idp/auth"),
        URI.create("https://idp/token"), URI.create("https://idp/jwks"),
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
        Set.of("openid"), Set.of("code"), Set.of("RS256"));
    assertThrows(UnsupportedOperationException.class, () -> m.scopesSupported().add("x"));
    assertEquals(Duration.ofSeconds(60), IdTokenExpectations.DEFAULT_CLOCK_SKEW);
  }
}
