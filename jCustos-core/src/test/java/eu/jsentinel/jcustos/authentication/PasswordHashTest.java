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
package eu.jsentinel.jcustos.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasswordHashTest {

  @Test
  @DisplayName("constructor rejects null algorithm / encoded / parameters")
  void rejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> new PasswordHash(null, "AAAA", Map.of()));
    assertThrows(NullPointerException.class,
        () -> new PasswordHash("pbkdf2", null, Map.of()));
    assertThrows(NullPointerException.class,
        () -> new PasswordHash("pbkdf2", "AAAA", null));
  }

  @Test
  @DisplayName("constructor rejects blank algorithm / encoded")
  void rejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordHash(" ", "AAAA", Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> new PasswordHash("pbkdf2", "  ", Map.of()));
  }

  @Test
  @DisplayName("parameters are defensively copied — caller mutations do not leak")
  void parametersAreCopied() {
    Map<String, String> caller = new HashMap<>();
    caller.put("k", "v");
    PasswordHash hash = new PasswordHash("pbkdf2", "AAAA", caller);

    caller.put("evil", "x");

    assertEquals(1, hash.parameters().size());
    assertEquals("v", hash.parameters().get("k"));
    assertThrows(UnsupportedOperationException.class,
        () -> hash.parameters().put("k", "x"));
  }

  @Test
  @DisplayName("intParameter parses the value or returns the default")
  void intParameter() {
    PasswordHash hash = new PasswordHash("pbkdf2", "AAAA",
        Map.of("iterations", "120000"));

    assertEquals(120_000, hash.intParameter("iterations", -1));
    assertEquals(-1, hash.intParameter("missing", -1));
  }

  @Test
  @DisplayName("intParameter returns the default when the value is unparseable")
  void intParameterUnparseable() {
    PasswordHash hash = new PasswordHash("pbkdf2", "AAAA",
        Map.of("iterations", "not-a-number"));

    assertEquals(0, hash.intParameter("iterations", 0));
  }
}
