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
package com.svenruppert.jsentinel.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("SessionId")
class SessionIdTest {

  @Test
  @DisplayName("constructor rejects null value")
  void rejectsNull() {
    assertThrows(IllegalArgumentException.class, () -> new SessionId(null));
  }

  @Test
  @DisplayName("constructor rejects empty string")
  void rejectsEmpty() {
    assertThrows(IllegalArgumentException.class, () -> new SessionId(""));
  }

  @Test
  @DisplayName("constructor rejects whitespace-only string")
  void rejectsBlank() {
    assertThrows(IllegalArgumentException.class, () -> new SessionId("   "));
  }

  @Test
  @DisplayName("constructor accepts a normal identifier")
  void acceptsNormalIdentifier() {
    assertEquals("sid-42", new SessionId("sid-42").value());
  }

  @Test
  @DisplayName("equals is value-based")
  void equalsIsValueBased() {
    assertEquals(new SessionId("a"), new SessionId("a"));
    assertNotEquals(new SessionId("a"), new SessionId("b"));
  }

  @Test
  @DisplayName("of(...) factory mirrors the constructor")
  void ofIsMirror() {
    assertEquals(new SessionId("x"), SessionId.of("x"));
  }

  @Test
  @DisplayName("of(...) propagates validation")
  void ofValidates() {
    assertThrows(IllegalArgumentException.class, () -> SessionId.of(null));
    assertThrows(IllegalArgumentException.class, () -> SessionId.of(""));
  }
}
