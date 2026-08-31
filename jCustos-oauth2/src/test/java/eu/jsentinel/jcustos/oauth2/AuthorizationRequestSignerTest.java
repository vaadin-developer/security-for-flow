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
package eu.jsentinel.jcustos.oauth2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.api.JwtSigningKey;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.jwt.impl.NimbusJwtSigner;
import eu.jsentinel.jcustos.jwt.impl.NimbusJwtValidator;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * No-mock JAR: a real RSA key signs the request object via the V00.77
 * {@link NimbusJwtSigner}, and the real {@link NimbusJwtValidator} verifies it. Proves
 * the signed {@code request} object carries the authorization-request params plus
 * {@code iss}/{@code aud}/{@code client_id} and verifies under the client's public key
 * (RFC 9101).
 */
@DisplayName("JAR — AuthorizationRequestSigner (RFC 9101)")
class AuthorizationRequestSignerTest {

  private static final String CLIENT = "rp-client";
  private static final String AUD = "https://op.example.com";
  private static final String KID = "jar-1";
  private static final Instant NOW = Instant.parse("2026-06-27T12:00:00Z");

  private final RSAKey rsa = newKey();

  private static RSAKey newKey() {
    try {
      return new RSAKeyGenerator(2048).keyID(KID).generate();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Test
  @DisplayName("the signed request object verifies and carries the request params + iss/aud")
  void signedRequestVerifies() throws Exception {
    JwtSigningKey key = new JwtSigningKey(rsa.toRSAPrivateKey(), JwsAlgorithm.RS256, Optional.of(KID));
    AuthorizationRequestSigner signer = new AuthorizationRequestSigner(new NimbusJwtSigner(), key, CLIENT);

    String requestObject = signer.sign(
        Map.of("response_type", "code", "scope", "openid profile", "redirect_uri",
            "https://rp.example.com/cb", "state", "xyz"),
        AUD);

    JwksClient keys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        try {
          return KID.equals(kid) ? Optional.of(rsa.toRSAPublicKey()) : Optional.empty();
        } catch (Exception e) {
          throw new IllegalStateException(e);
        }
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(CLIENT), Set.of(AUD), false, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.empty());
    NimbusJwtValidator validator = new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, () -> NOW);

    ValidatedJwt jwt = validator.validate(requestObject).getOrThrow();
    assertEquals("code", jwt.claim("response_type", String.class).orElse(null));
    assertEquals("openid profile", jwt.claim("scope", String.class).orElse(null));
    assertEquals(CLIENT, jwt.claim("client_id", String.class).orElse(null));
    assertEquals(CLIENT, jwt.issuer().orElse(null));
    assertTrue(jwt.audience().orElse(java.util.List.of()).contains(AUD));
  }
}
