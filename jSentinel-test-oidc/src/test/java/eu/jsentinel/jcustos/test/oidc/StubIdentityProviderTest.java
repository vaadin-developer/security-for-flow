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
package eu.jsentinel.jcustos.test.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.identity.oidc.DefaultClaimsToSubjectMapper;
import eu.jsentinel.jcustos.identity.oidc.DefaultIdTokenValidator;
import eu.jsentinel.jcustos.identity.oidc.HttpOidcDiscoveryClient;
import eu.jsentinel.jcustos.identity.oidc.HttpUserInfoClient;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.impl.NimbusJwtValidator;
import eu.jsentinel.jcustos.oauth2.HttpTokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.PkceVerifier;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;
import eu.jsentinel.jcustos.oidc.api.IdTokenExpectations;
import eu.jsentinel.jcustos.oidc.api.OidcProviderMetadata;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

import java.net.URI;
import java.net.http.HttpClient;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("StubIdentityProvider — drives the real OIDC RP pipeline end to end (no mocks)")
class StubIdentityProviderTest {

  private StubIdentityProvider idp;
  private final MockClock clock = MockClock.fixed();

  @BeforeEach
  void start() {
    System.setProperty("jsentinel.dev", "true");
    idp = StubIdentityProvider.start("rp", clock)
        .withIdTokenClaims(Map.of("sub", "alice", "nonce", "n-1"))
        .withUserInfoClaims(Map.of("sub", "alice", "email", "alice@example.com", "name", "Alice"));
  }

  @AfterEach
  void stop() {
    idp.close();
    System.clearProperty("jsentinel.dev");
  }

  private NimbusJwtValidator jwtValidator() {
    PublicKey key;
    try {
      key = idp.publicSigningKey().toPublicKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    JwksClient keys = new JwksClient() {
      @Override public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return Optional.of(key);
      }

      @Override public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, clock.get(), Duration.ofMinutes(5), Optional.empty());
      }
    };
    return new NimbusJwtValidator(AlgorithmProfile.STRICT_MODERN.toAllowList(), keys,
        new ClaimExpectations(Optional.of(idp.issuer()), Set.of("rp"),
            true, false, false, false, ClockSkewPolicy.DEFAULT, Optional.empty()),
        clock);
  }

  @Test
  @DisplayName("discovery -> token exchange -> id-token validation -> userinfo -> subject")
  void fullPipeline() {
    HttpClient http = HttpClient.newHttpClient();

    // 1. discovery
    OidcProviderMetadata md = new HttpOidcDiscoveryClient(http)
        .discover(idp.issuerUri()).toOptional().orElseThrow();
    assertEquals(idp.tokenEndpoint(), md.tokenEndpoint());
    assertEquals(idp.userInfoEndpoint(), md.userinfoEndpoint().orElseThrow());

    // 2. token exchange -> a real signed id_token
    TokenResponse tokens = new HttpTokenEndpointClient(md.tokenEndpoint(),
        new ClientAuthentication.NoneAuthentication("rp"), http, clock)
        .exchangeCode("auth-code", URI.create("https://app.example/cb"), PkceVerifier.generate())
        .toOptional().orElseThrow();
    assertTrue(tokens.idToken().isPresent());

    // 3. id-token validation against the discovered jwks key
    ValidatedIdToken vit = new DefaultIdTokenValidator(jwtValidator(), clock)
        .validate(tokens.idToken().orElseThrow(),
            IdTokenExpectations.of(idp.issuer(), "rp", Optional.of("n-1")))
        .toOptional().orElseThrow();
    assertEquals(Optional.of("alice"), vit.subject());

    // 4. userinfo
    UserInfoResponse userInfo = new HttpUserInfoClient(http, md.userinfoEndpoint().orElseThrow())
        .fetch(tokens.accessToken()).toOptional().orElseThrow();
    assertEquals("alice", userInfo.subject());

    // 5. claims -> subject
    JCustosSubject subject = new DefaultClaimsToSubjectMapper().map(vit, Optional.of(userInfo));
    assertEquals(idp.issuer() + "#alice", subject.subjectId());
    assertEquals("Alice", subject.displayName());
  }
}
