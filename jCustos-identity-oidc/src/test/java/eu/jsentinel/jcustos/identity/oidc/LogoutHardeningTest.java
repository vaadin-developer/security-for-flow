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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import eu.jsentinel.jcustos.jwt.api.AlgorithmProfile;
import eu.jsentinel.jcustos.jwt.api.ClaimExpectations;
import eu.jsentinel.jcustos.jwt.api.ClockSkewPolicy;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;
import eu.jsentinel.jcustos.jwt.impl.NimbusJwtValidator;
import eu.jsentinel.jcustos.oidc.api.BackChannelLogoutOutcome;
import eu.jsentinel.jcustos.oidc.api.LogoutTokenValidationError;
import eu.jsentinel.jcustos.replay.impl.InMemoryJtiStore;

import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * No-mock Back-Channel + Front-Channel Logout: real RSA-signed logout tokens, the real
 * {@link NimbusJwtValidator}, the real {@link InMemoryJtiStore} +
 * {@link InMemorySessionRegistry}. Proves accept-on-valid + reject on each
 * OIDC Back-Channel Logout 1.0 §2.4 failure, plus session termination.
 */
@DisplayName("Logout hardening — back-channel + front-channel (OIDC BCL/FCL 1.0)")
class LogoutHardeningTest {

  private static final String ISSUER = "https://op.example.com";
  private static final String CLIENT = "rp-client-1";
  private static final String KID = "k-logout";
  private static final Instant NOW = Instant.parse("2026-06-27T12:00:00Z");

  private final RSAKey rsa = newKey();

  private static RSAKey newKey() {
    try {
      return new RSAKeyGenerator(2048).keyID(KID).generate();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private PublicKey publicKey() {
    try {
      return rsa.toRSAPublicKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private NimbusJwtValidator jwtValidator() {
    JwksClient keys = new JwksClient() {
      @Override
      public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return KID.equals(kid) ? Optional.of(publicKey()) : Optional.empty();
      }

      @Override
      public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, NOW, Duration.ofMinutes(5), Optional.empty());
      }
    };
    // exp not required for a logout token; iat is.
    ClaimExpectations expectations = new ClaimExpectations(
        Optional.of(ISSUER), Set.of(CLIENT), false, false, false, false,
        ClockSkewPolicy.DEFAULT, Optional.empty());
    return new NimbusJwtValidator(
        AlgorithmProfile.STRICT_MODERN.toAllowList(), keys, expectations, () -> NOW);
  }

  private DefaultLogoutTokenValidator validator() {
    // JS-SEC-041: the validator's jti-retention window is anchored on ITS clock (first-seen),
    // pinned here to NOW so both the validator and the jti store share one deterministic clock.
    return new DefaultLogoutTokenValidator(
        jwtValidator(), new InMemoryJtiStore(1000, () -> NOW), () -> NOW);
  }

  /** Like {@link #sign} but WITHOUT an issueTime — an iat-less logout token. */
  private String signNoIat(JWTClaimsSet.Builder claims) {
    try {
      claims.issuer(ISSUER).audience(CLIENT).jwtID("jti-noiat");
      SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims.build());
      jwt.sign(new RSASSASigner(rsa));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private String sign(JWTClaimsSet.Builder claims) {
    try {
      claims.issuer(ISSUER).audience(CLIENT).issueTime(Date.from(NOW)).jwtID("jti-" + System.identityHashCode(claims));
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), claims.build());
      jwt.sign(new RSASSASigner(rsa));
      return jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static JWTClaimsSet.Builder logoutClaims() {
    return new JWTClaimsSet.Builder()
        .subject("alice")
        .claim("sid", "sess-1")
        .claim("events", Map.of(DefaultLogoutTokenValidator.BACKCHANNEL_LOGOUT_EVENT, Map.of()));
  }

  @Test
  @DisplayName("a valid logout token validates and terminates the registered session")
  void validLogoutTerminatesSession() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sess-1"), "rp-session-aaa");
    BackChannelLogoutReceiver receiver = new BackChannelLogoutReceiver(validator(), registry);

    BackChannelLogoutOutcome outcome = receiver.receive(sign(logoutClaims()));
    BackChannelLogoutOutcome.Accepted accepted = assertInstanceOf(BackChannelLogoutOutcome.Accepted.class, outcome);
    assertEquals(Set.of("rp-session-aaa"), accepted.terminatedSessionIds());
  }

  @Test
  @DisplayName("a present nonce is rejected (logout tokens must not carry one)")
  void noncePresentRejected() {
    var err = validator().validate(sign(logoutClaims().claim("nonce", "n-1"))).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.NonceMustNotBePresent.class, err);
  }

  @Test
  @DisplayName("a token without the back-channel-logout event is rejected (an ID token cannot log out)")
  void missingEventRejected() {
    String idTokenShaped = sign(new JWTClaimsSet.Builder().subject("alice").claim("sid", "sess-1"));
    var err = validator().validate(idTokenShaped).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.MissingBackchannelEvent.class, err);
  }

  @Test
  @DisplayName("a token with neither sub nor sid is rejected")
  void missingSubAndSidRejected() {
    String token = sign(new JWTClaimsSet.Builder()
        .claim("events", Map.of(DefaultLogoutTokenValidator.BACKCHANNEL_LOGOUT_EVENT, Map.of())));
    var err = validator().validate(token).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.MissingSubjectAndSid.class, err);
  }

  @Test
  @DisplayName("a token signed by the wrong key is rejected as JwtInvalid")
  void forgedSignatureRejected() {
    RSAKey attacker = newKey();
    String forged;
    try {
      JWTClaimsSet.Builder c = logoutClaims().issuer(ISSUER).audience(CLIENT).issueTime(Date.from(NOW)).jwtID("x");
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), c.build());
      jwt.sign(new RSASSASigner(attacker));
      forged = jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    var err = validator().validate(forged).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.JwtInvalid.class, err);
  }

  @Test
  @DisplayName("a logout token without the required jti is rejected")
  void missingJtiRejected() {
    String token;
    try {
      JWTClaimsSet.Builder c = logoutClaims().issuer(ISSUER).audience(CLIENT).issueTime(Date.from(NOW));
      SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KID).build(), c.build());
      jwt.sign(new RSASSASigner(rsa));
      token = jwt.serialize();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    var err = validator().validate(token).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.MissingJwtId.class, err);
  }

  @Test
  @DisplayName("a replayed logout token (same jti) is rejected the second time")
  void replayRejected() {
    DefaultLogoutTokenValidator v = validator();
    String token = sign(logoutClaims());
    assertTrue(v.validate(token).isSuccess());
    var err = v.validate(token).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.Replay.class, err);
  }

  @Test
  @DisplayName("JS-SEC-041: a replayed logout token WITHOUT iat is still caught (first-seen window, not iat/EPOCH)")
  void replayRejectedForIatLessToken() {
    DefaultLogoutTokenValidator v = validator();
    String token = signNoIat(logoutClaims());
    // an iat-less logout token still validates the first time (iat is not required by this config)...
    assertTrue(v.validate(token).isSuccess());
    // ...and its replay MUST be caught. Previously the window was iat.orElse(EPOCH)+10min → a past
    // expiry, so the jti store never flagged the second use (replay protection silently off).
    var err = v.validate(token).fold(ok -> null, e -> e);
    assertInstanceOf(LogoutTokenValidationError.Replay.class, err);
  }

  @Test
  @DisplayName("front-channel logout terminates on a trusted issuer and ignores a forged one")
  void frontChannel() {
    InMemorySessionRegistry registry = new InMemorySessionRegistry();
    registry.register(ISSUER, "alice", Optional.of("sess-9"), "rp-session-fc");
    FrontChannelLogoutEndpoint endpoint = new FrontChannelLogoutEndpoint(ISSUER, registry);

    assertEquals(Set.of(), endpoint.logout("https://evil.example.com", Optional.of("sess-9")));
    assertEquals(Set.of("rp-session-fc"), endpoint.logout(ISSUER, Optional.of("sess-9")));
  }
}
