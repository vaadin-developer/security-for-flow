package com.svenruppert.jsentinel.events.testkit;

/*-
 * #%L
 * jSentinel Events — Contract testkit
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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithm;
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
@ExperimentalJSentinelApi
@DisplayName("SignatureAlgorithm — contract")
public interface SignatureAlgorithmContract {

  SignatureAlgorithm newAlgorithm();

  byte[] DATA = "the signature base".getBytes(StandardCharsets.UTF_8);

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
    byte[] signature = algorithm.sign(DATA, keyPair.getPrivate());
    assertTrue(algorithm.verify(DATA, signature, keyPair.getPublic()));
  }

  @Test
  @DisplayName("a tampered payload fails verification")
  default void tamperedFails() {
    SignatureAlgorithm algorithm = newAlgorithm();
    KeyPair keyPair = algorithm.generateKeyPair();
    byte[] signature = algorithm.sign(DATA, keyPair.getPrivate());
    byte[] tampered = "the signature base!".getBytes(StandardCharsets.UTF_8);
    assertFalse(algorithm.verify(tampered, signature, keyPair.getPublic()));
  }

  @Test
  @DisplayName("structurally invalid signature bytes return false, not an exception")
  default void garbageReturnsFalse() {
    SignatureAlgorithm algorithm = newAlgorithm();
    KeyPair keyPair = algorithm.generateKeyPair();
    assertFalse(algorithm.verify(DATA, new byte[]{0, 1, 2, 3}, keyPair.getPublic()));
  }
}
