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
package eu.jsentinel.jcustos.authorization.api.tenant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("TenantId")
class TenantIdTest {

  @Test
  @DisplayName("constructor rejects null value")
  void rejectsNull() {
    assertThrows(IllegalArgumentException.class, () -> new TenantId(null));
  }

  @Test
  @DisplayName("constructor rejects empty string")
  void rejectsEmpty() {
    assertThrows(IllegalArgumentException.class, () -> new TenantId(""));
  }

  @Test
  @DisplayName("constructor rejects whitespace-only string")
  void rejectsBlank() {
    assertThrows(IllegalArgumentException.class, () -> new TenantId("   "));
    assertThrows(IllegalArgumentException.class, () -> new TenantId("\t"));
  }

  @Test
  @DisplayName("constructor accepts a normal identifier")
  void acceptsNormalIdentifier() {
    TenantId id = new TenantId("acme");
    assertEquals("acme", id.value());
  }

  @Test
  @DisplayName("equals is value-based")
  void equalsIsValueBased() {
    assertEquals(new TenantId("acme"), new TenantId("acme"));
    assertNotEquals(new TenantId("acme"), new TenantId("globex"));
  }

  @Test
  @DisplayName("of(...) factory is a constructor mirror")
  void ofIsMirror() {
    assertEquals(new TenantId("acme"), TenantId.of("acme"));
  }

  @Test
  @DisplayName("of(...) propagates the same validation rules")
  void ofValidates() {
    assertThrows(IllegalArgumentException.class, () -> TenantId.of(null));
    assertThrows(IllegalArgumentException.class, () -> TenantId.of(""));
  }

  @Test
  @DisplayName("DEFAULT is the literal 'default' tenant")
  void defaultIsLiteralDefault() {
    assertEquals("default", TenantId.DEFAULT.value());
  }

  @Test
  @DisplayName("DEFAULT is a singleton constant — every reference is the same instance")
  void defaultIsSingleton() {
    assertSame(TenantId.DEFAULT, TenantId.DEFAULT);
  }

  @Test
  @DisplayName("DEFAULT equals an independently constructed TenantId(\"default\")")
  void defaultEqualsConstructed() {
    assertEquals(TenantId.DEFAULT, new TenantId("default"));
  }
}
