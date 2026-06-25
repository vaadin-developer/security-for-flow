package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.jwt.api.JwtValidationError.ClaimInvalid;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError.Expired;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError.JweNotSupported;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError.MalformedJwt;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError.NotYetValid;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError.SignatureInvalid;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError.UnknownKid;
import com.svenruppert.jsentinel.jwt.api.JwtValidationError.UnsupportedAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JwtValidationError sealed hierarchy")
class JwtValidationErrorTest {

  @Test
  @DisplayName("an exhaustive switch (no default) covers every variant")
  void exhaustiveSwitchCoversAllVariants() {
    List<JwtValidationError> all = List.of(
        new MalformedJwt("m"),
        new SignatureInvalid("s"),
        new UnsupportedAlgorithm("jwt/algorithm-not-in-allow-list", "u"),
        new UnknownKid("k"),
        new Expired("e"),
        new NotYetValid("n"),
        new ClaimInvalid("claims/issuer-mismatch", "c"),
        new JweNotSupported("j"));

    for (JwtValidationError error : all) {
      // a switch without a default forces compile-time exhaustiveness over the
      // sealed hierarchy — adding a variant without updating this fails to compile.
      String kind = switch (error) {
        case MalformedJwt e -> e.code();
        case SignatureInvalid e -> e.code();
        case UnsupportedAlgorithm e -> e.code();
        case UnknownKid e -> e.code();
        case Expired e -> e.code();
        case NotYetValid e -> e.code();
        case ClaimInvalid e -> e.code();
        case JweNotSupported e -> e.code();
      };
      assertEquals(error.code(), kind);
      assertTrue(error.code().contains("/"), "code is namespaced: " + error.code());
    }
  }

  @Test
  @DisplayName("fixed-code variants expose their stable kebab-case code")
  void fixedCodes() {
    assertEquals("jwt/malformed", new MalformedJwt("x").code());
    assertEquals("jwt/signature-invalid", new SignatureInvalid("x").code());
    assertEquals("jwt/unknown-kid", new UnknownKid("x").code());
    assertEquals("jwt/expired", new Expired("x").code());
    assertEquals("jwt/not-yet-valid", new NotYetValid("x").code());
    assertEquals("jwt/jwe-not-supported", new JweNotSupported("x").code());
  }

  @Test
  @DisplayName("UnsupportedAlgorithm and ClaimInvalid carry an explicit sub-case code")
  void parameterisedCodes() {
    assertEquals("jwt/algorithm-confusion-suspected",
        new UnsupportedAlgorithm("jwt/algorithm-confusion-suspected", "x").code());
    assertEquals("claims/exp-missing",
        new ClaimInvalid("claims/exp-missing", "x").code());
  }
}
