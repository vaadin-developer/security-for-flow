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

import eu.jsentinel.jcustos.events.api.SignatureAlgorithmId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SignatureAlgorithms registry")
class SignatureAlgorithmsTest {

  @Test
  @DisplayName("defaults() resolves both built-in providers by id")
  void defaultsResolveBuiltins() {
    SignatureAlgorithms registry = SignatureAlgorithms.defaults();
    assertEquals(2, registry.size());
    assertEquals(SignatureAlgorithmId.ED25519,
        registry.require(SignatureAlgorithmId.ED25519).id());
    assertEquals(SignatureAlgorithmId.ECDSA_P256,
        registry.require(SignatureAlgorithmId.ECDSA_P256).id());
  }

  @Test
  @DisplayName("require throws for an unknown id")
  void requireThrowsOnUnknown() {
    SignatureAlgorithms registry = SignatureAlgorithms.defaults();
    assertTrue(registry.find(SignatureAlgorithmId.of("RSA-PSS")).isEmpty());
    assertThrows(IllegalArgumentException.class,
        () -> registry.require(SignatureAlgorithmId.of("RSA-PSS")));
  }

  @Test
  @DisplayName("discover() includes the ServiceLoader-registered built-ins")
  void discoverFindsServiceLoaderProviders() {
    SignatureAlgorithms registry = SignatureAlgorithms.discover();
    assertTrue(registry.find(SignatureAlgorithmId.ED25519).isPresent());
    assertTrue(registry.find(SignatureAlgorithmId.ECDSA_P256).isPresent());
  }
}
