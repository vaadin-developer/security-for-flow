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
package com.svenruppert.jsentinel.dpop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.svenruppert.jsentinel.dpop.DpopValidationError.AccessTokenHashMismatch;
import com.svenruppert.jsentinel.dpop.DpopValidationError.HtmMismatch;
import com.svenruppert.jsentinel.dpop.DpopValidationError.HtuMismatch;
import com.svenruppert.jsentinel.dpop.DpopValidationError.ProofExpired;
import com.svenruppert.jsentinel.dpop.DpopValidationError.Replay;
import com.svenruppert.jsentinel.replay.impl.InMemoryJtiStore;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * No-mock DPoP round-trip: real RSA / EC keys, real Nimbus signing + verification, the
 * real {@link InMemoryJtiStore} for replay. Proves accept-on-valid + reject on each
 * RFC 9449 §4.3 failure.
 */
@DisplayName("DPoP proof — generate + validate round-trip (RFC 9449)")
class DpopProofRoundTripTest {

  private static final Set<String> ALG = Set.of("RS256", "ES256");
  private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-06-27T12:00:00Z"));
  private final DpopProofGenerator generator =
      new DpopProofGenerator(now::get, () -> "jti-" + now.get().getEpochSecond());

  private NimbusDpopProofValidator validatorWith(InMemoryJtiStore store) {
    return new NimbusDpopProofValidator(ALG, store, now::get);
  }

  private static RSAKey rsaKey() throws Exception {
    return new RSAKeyGenerator(2048).generate();
  }

  private static ECKey ecKey() throws Exception {
    return new ECKeyGenerator(Curve.P_256).generate();
  }

  @Test
  @DisplayName("a freshly generated RSA proof validates; thumbprint matches the key")
  void rsaRoundTrip() throws Exception {
    RSAKey key = rsaKey();
    URI uri = URI.create("https://api.example.com/resource");
    String proof = generator.generate(key, "GET", uri, Optional.empty());

    ValidatedDpopProof validated = validatorWith(new InMemoryJtiStore(1000, now::get))
        .validate(DpopValidationRequest.of(proof, "GET", uri))
        .getOrThrow();

    assertEquals("GET", validated.httpMethod());
    assertEquals(new JwkThumbprint(key.computeThumbprint().toString()), validated.thumbprint());
  }

  @Test
  @DisplayName("an EC proof validates")
  void ecRoundTrip() throws Exception {
    JWK key = ecKey();
    URI uri = URI.create("https://api.example.com/ec");
    String proof = generator.generate(key, "POST", uri, Optional.empty());
    assertTrue(validatorWith(new InMemoryJtiStore(1000, now::get))
        .validate(DpopValidationRequest.of(proof, "POST", uri)).isSuccess());
  }

  @Test
  @DisplayName("the same proof presented twice is a replay")
  void replayRejected() throws Exception {
    RSAKey key = rsaKey();
    URI uri = URI.create("https://api.example.com/resource");
    String proof = generator.generate(key, "GET", uri, Optional.empty());
    NimbusDpopProofValidator validator = validatorWith(new InMemoryJtiStore(1000, now::get));

    assertTrue(validator.validate(DpopValidationRequest.of(proof, "GET", uri)).isSuccess());
    DpopValidationError err = validator.validate(DpopValidationRequest.of(proof, "GET", uri))
        .fold(ok -> null, e -> e);
    assertInstanceOf(Replay.class, err);
  }

  @Test
  @DisplayName("htm and htu mismatches are rejected")
  void bindingMismatchRejected() throws Exception {
    RSAKey key = rsaKey();
    URI uri = URI.create("https://api.example.com/resource");
    String proof = generator.generate(key, "GET", uri, Optional.empty());

    assertInstanceOf(HtmMismatch.class, validatorWith(new InMemoryJtiStore(1000, now::get))
        .validate(DpopValidationRequest.of(proof, "POST", uri)).fold(ok -> null, e -> e));
    assertInstanceOf(HtuMismatch.class, validatorWith(new InMemoryJtiStore(1000, now::get))
        .validate(DpopValidationRequest.of(proof, "GET", URI.create("https://api.example.com/other")))
        .fold(ok -> null, e -> e));
  }

  @Test
  @DisplayName("ath binds the proof to a presented access token")
  void athBinding() throws Exception {
    RSAKey key = rsaKey();
    URI uri = URI.create("https://api.example.com/resource");
    String token = "access-token-xyz";
    String proof = generator.generate(key, "GET", uri, Optional.of(token));

    assertTrue(validatorWith(new InMemoryJtiStore(1000, now::get))
        .validate(DpopValidationRequest.boundTo(proof, "GET", uri, token)).isSuccess());
    assertInstanceOf(AccessTokenHashMismatch.class, validatorWith(new InMemoryJtiStore(1000, now::get))
        .validate(DpopValidationRequest.boundTo(proof, "GET", uri, "wrong-token")).fold(ok -> null, e -> e));
  }

  @Test
  @DisplayName("a proof older than the freshness window is rejected")
  void staleProofRejected() throws Exception {
    RSAKey key = rsaKey();
    URI uri = URI.create("https://api.example.com/resource");
    String proof = generator.generate(key, "GET", uri, Optional.empty());
    now.set(now.get().plusSeconds(120)); // beyond the 60s default maxAge
    assertInstanceOf(ProofExpired.class, validatorWith(new InMemoryJtiStore(1000, now::get))
        .validate(DpopValidationRequest.of(proof, "GET", uri)).fold(ok -> null, e -> e));
  }
}
