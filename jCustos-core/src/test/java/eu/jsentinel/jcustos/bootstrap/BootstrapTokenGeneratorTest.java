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
package eu.jsentinel.jcustos.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BootstrapTokenGenerator")
class BootstrapTokenGeneratorTest {

  private final BootstrapTokenGenerator generator = new BootstrapTokenGenerator();

  @Test
  @DisplayName("emits 5 groups of 4 ambiguity-free characters separated by '-'")
  void shape() {
    String value = generator.generate().value();
    assertTrue(value.matches("[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}"),
        "Token did not match expected shape: " + value);
    assertFalse(value.contains("0"));
    assertFalse(value.contains("1"));
    assertFalse(value.contains("O"));
    assertFalse(value.contains("I"));
  }

  @Test
  @DisplayName("100 generated tokens are unique")
  void uniqueness() {
    Set<String> tokens = new HashSet<>();
    for (int i = 0; i < 100; i++) tokens.add(generator.generate().value());
    assertEquals(100, tokens.size());
  }
}
