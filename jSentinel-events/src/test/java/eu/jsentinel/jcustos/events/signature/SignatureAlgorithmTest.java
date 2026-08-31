package eu.jsentinel.jcustos.events.signature;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SignatureAlgorithm providers (real JCA)")
class SignatureAlgorithmTest {

  static Stream<SignatureAlgorithm> providers() {
    return Stream.of(new Ed25519SignatureAlgorithm(), new EcdsaP256SignatureAlgorithm());
  }

  private static final byte[] DATA = "the signature base".getBytes(StandardCharsets.UTF_8);

  @ParameterizedTest
  @MethodSource("providers")
  @DisplayName("a fresh signature verifies against the matching public key")
  void roundTrip(SignatureAlgorithm algorithm) {
    KeyPair keyPair = algorithm.generateKeyPair();
    byte[] signature = algorithm.sign(DATA, keyPair.getPrivate());
    assertTrue(algorithm.verify(DATA, signature, keyPair.getPublic()));
  }

  @ParameterizedTest
  @MethodSource("providers")
  @DisplayName("a tampered payload fails verification")
  void tamperedDataFails(SignatureAlgorithm algorithm) {
    KeyPair keyPair = algorithm.generateKeyPair();
    byte[] signature = algorithm.sign(DATA, keyPair.getPrivate());
    byte[] tampered = "the signature base!".getBytes(StandardCharsets.UTF_8);
    assertFalse(algorithm.verify(tampered, signature, keyPair.getPublic()));
  }

  @ParameterizedTest
  @MethodSource("providers")
  @DisplayName("a signature from a different key fails verification")
  void wrongKeyFails(SignatureAlgorithm algorithm) {
    KeyPair signer = algorithm.generateKeyPair();
    KeyPair other = algorithm.generateKeyPair();
    byte[] signature = algorithm.sign(DATA, signer.getPrivate());
    assertFalse(algorithm.verify(DATA, signature, other.getPublic()));
  }

  @ParameterizedTest
  @MethodSource("providers")
  @DisplayName("structurally invalid signature bytes return false, not an exception")
  void garbageSignatureReturnsFalse(SignatureAlgorithm algorithm) {
    KeyPair keyPair = algorithm.generateKeyPair();
    assertFalse(algorithm.verify(DATA, new byte[]{0, 1, 2, 3}, keyPair.getPublic()));
  }
}
