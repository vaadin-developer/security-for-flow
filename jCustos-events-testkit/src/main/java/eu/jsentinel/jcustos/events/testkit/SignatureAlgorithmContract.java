package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link SignatureAlgorithm} implementations.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
@DisplayName("SignatureAlgorithm — contract")
public interface SignatureAlgorithmContract {

  SignatureAlgorithm newAlgorithm();

  // V00.76.10 H2: a fresh array per call instead of a shared mutable static
  // interface constant (SpotBugs MS_OOI_PKGPROTECT — interface fields are
  // implicitly public, so a byte[] constant is a process-wide mutable exposure).
  default byte[] data() {
    return "the signature base".getBytes(StandardCharsets.UTF_8);
  }

  @Test
  @DisplayName("id is non-null")
  default void idNonNull() {
    assertNotNull(newAlgorithm().id());
  }

  @Test
  @DisplayName("a fresh signature verifies against the matching public key")
  default void roundTrip() {
    SignatureAlgorithm algorithm = newAlgorithm();
    KeyPair keyPair = algorithm.generateKeyPair();
    byte[] signature = algorithm.sign(data(), keyPair.getPrivate());
    assertTrue(algorithm.verify(data(), signature, keyPair.getPublic()));
  }

  @Test
  @DisplayName("a tampered payload fails verification")
  default void tamperedFails() {
    SignatureAlgorithm algorithm = newAlgorithm();
    KeyPair keyPair = algorithm.generateKeyPair();
    byte[] signature = algorithm.sign(data(), keyPair.getPrivate());
    byte[] tampered = "the signature base!".getBytes(StandardCharsets.UTF_8);
    assertFalse(algorithm.verify(tampered, signature, keyPair.getPublic()));
  }

  @Test
  @DisplayName("structurally invalid signature bytes return false, not an exception")
  default void garbageReturnsFalse() {
    SignatureAlgorithm algorithm = newAlgorithm();
    KeyPair keyPair = algorithm.generateKeyPair();
    assertFalse(algorithm.verify(data(), new byte[]{0, 1, 2, 3}, keyPair.getPublic()));
  }
}
