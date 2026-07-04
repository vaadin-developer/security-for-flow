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
package com.svenruppert.jsentinel.oauth2.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("OAuth2Json.parseScopes — JS-SEC-034 duplicate-tolerant scope parsing")
class OAuth2JsonScopeTest {

  @Test
  @DisplayName("duplicate scope values are de-duplicated, not rejected")
  void deduplicatesDuplicateScopes() {
    assertEquals(Set.of("read"), OAuth2Json.parseScopes("read read"));
  }

  @Test
  @DisplayName("consecutive spaces yield no empty tokens")
  void toleratesConsecutiveSpaces() {
    assertEquals(Set.of("a", "b"), OAuth2Json.parseScopes("a   b"));
  }

  @Test
  @DisplayName("leading/trailing whitespace and a mix of dup + spaces are handled")
  void trimsAndDedups() {
    assertEquals(Set.of("read", "write"), OAuth2Json.parseScopes("  read   read write  "));
  }

  @Test
  @DisplayName("null and blank yield an empty set")
  void nullAndBlankAreEmpty() {
    assertEquals(Set.of(), OAuth2Json.parseScopes(null));
    assertEquals(Set.of(), OAuth2Json.parseScopes("   "));
  }
}
