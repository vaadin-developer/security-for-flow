package eu.jsentinel.jcustos.propagation.oidc.inbound;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.OidcAccessToken;
import eu.jsentinel.jcustos.jwt.api.JoseHeader;
import eu.jsentinel.jcustos.jwt.api.JwtValidationError;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OidcInboundTokenValidator — inbound validation via the core SPI (no mocks)")
class OidcInboundTokenValidatorTest {

  private final OidcInboundTokenValidator inbound = new OidcInboundTokenValidator();

  @AfterEach
  void reset() {
    JSentinelServiceResolver.setJwtValidator(null);
  }

  private static ValidatedJwt validatedFor(String token) {
    return new ValidatedJwt(token,
        new JoseHeader("RS256", Optional.of("k1"), Optional.empty()),
        Map.of("iss", "https://idp.example/", "sub", "alice"),
        Instant.EPOCH);
  }

  /** A real (non-mock) validator that accepts exactly the token "good". */
  private void installValidatorAccepting(String accepted) {
    JwtValidator validator = compact -> accepted.equals(compact)
        ? Result.success(validatedFor(compact))
        : Result.failure(new JwtValidationError.SignatureInvalid("nope"));
    JSentinelServiceResolver.setJwtValidator(validator);
  }

  @Test
  @DisplayName("a valid token yields an OidcAccessToken carrying the validation result")
  void validTokenYieldsOidcAccessToken() {
    installValidatorAccepting("good");
    Optional<OidcAccessToken> result = inbound.validate("good");
    assertTrue(result.isPresent());
    assertEquals("good", result.get().value());
    assertSame(validatedFor("good").header().alg(),
        result.get().validated().orElseThrow().header().alg());
  }

  @Test
  @DisplayName("a token the validator rejects yields empty")
  void rejectedTokenYieldsEmpty() {
    installValidatorAccepting("good");
    assertTrue(inbound.validate("bad").isEmpty());
  }

  @Test
  @DisplayName("with no validator registered, validation is empty (not an error)")
  void noValidatorYieldsEmpty() {
    assertTrue(inbound.validate("good").isEmpty());
  }

  @Test
  @DisplayName("a blank token is empty without consulting the validator")
  void blankTokenYieldsEmpty() {
    installValidatorAccepting("good");
    assertTrue(inbound.validate("   ").isEmpty());
  }
}
