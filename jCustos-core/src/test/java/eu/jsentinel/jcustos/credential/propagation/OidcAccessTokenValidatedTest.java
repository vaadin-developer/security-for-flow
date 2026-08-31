package eu.jsentinel.jcustos.credential.propagation;

import eu.jsentinel.jcustos.jwt.api.JoseHeader;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OidcAccessToken.fromValidated (V00.76 additive field)")
class OidcAccessTokenValidatedTest {

  @Test
  @DisplayName("derives expiry / audience / issuer-hash and carries the ValidatedJwt")
  void derivesMetadataAndCarriesValidated() {
    ValidatedJwt v = new ValidatedJwt("aaa.bbb.ccc",
        new JoseHeader("RS256", Optional.of("k1"), Optional.empty()),
        Map.of("iss", "https://idp.example/", "exp", 1000L, "aud", List.of("api.example")),
        Instant.EPOCH);

    OidcAccessToken token = OidcAccessToken.fromValidated("aaa.bbb.ccc", v);

    assertEquals("aaa.bbb.ccc", token.value());
    assertEquals(Optional.of(Instant.ofEpochSecond(1000)), token.expiresAt());
    assertEquals(Optional.of("api.example"), token.audience());
    assertEquals(64, token.issuerHash().orElseThrow().length(), "SHA-256 hex is 64 chars");
    assertSame(v, token.validated().orElseThrow());
    assertFalse(token.toString().contains("aaa.bbb.ccc"), "value stays masked in toString");
  }
}
