package eu.jsentinel.jcustos.events.testkit;

/*-
 * #%L
 * jCustos Events — Contract testkit
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.keys.JCustosEventSigningKeyProvider;
import eu.jsentinel.jcustos.events.keys.JCustosEventVerificationKeyResolver;
import eu.jsentinel.jcustos.events.keys.KeyStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for key-management implementations that provide both the
 * signer and verifier SPIs over the same key material.
 *
 * @param <K> a type implementing both key SPIs
 * @since 00.75.00
 */
@ExperimentalJCustosApi
@DisplayName("KeyManagement — contract")
public interface KeyManagementContract<
    K extends JCustosEventSigningKeyProvider & JCustosEventVerificationKeyResolver> {

  K newKeyManagement();

  @Test
  @DisplayName("the current key signs verifiably and its verification key resolves")
  default void currentKeySignsAndResolves() {
    K km = newKeyManagement();
    KeyId current = km.currentKeyId();
    assertTrue(km.resolveVerificationKey(current).isPresent());
    byte[] data = "base".getBytes(StandardCharsets.UTF_8);
    byte[] signature = km.currentAlgorithm().sign(data, km.currentSigningKey());
    assertTrue(km.currentAlgorithm()
        .verify(data, signature, km.resolveVerificationKey(current).orElseThrow()));
  }

  @Test
  @DisplayName("the current key reports ACTIVE; an unknown key reports UNKNOWN")
  default void keyStatuses() {
    K km = newKeyManagement();
    assertEquals(KeyStatus.ACTIVE, km.keyStatus(km.currentKeyId()));
    assertEquals(KeyStatus.UNKNOWN, km.keyStatus(KeyId.of("definitely-not-a-key")));
  }
}
