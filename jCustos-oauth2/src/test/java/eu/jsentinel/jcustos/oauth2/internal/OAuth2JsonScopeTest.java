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
package eu.jsentinel.jcustos.oauth2.internal;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

  @Test
  @DisplayName("JS-SEC-043: stringOrArray reads a scalar `aud` as a single-element set")
  void audScalar() {
    assertEquals(Set.of("rs-a"),
        OAuth2Json.stringOrArray("{\"active\":true,\"aud\":\"rs-a\"}", "aud"));
  }

  @Test
  @DisplayName("JS-SEC-043: stringOrArray reads an array-form `aud` as all its elements (was silently dropped)")
  void audArray() {
    assertEquals(Set.of("rs-a", "rs-b"),
        OAuth2Json.stringOrArray("{\"active\":true,\"aud\":[\"rs-a\",\"rs-b\"],\"iss\":\"op\"}", "aud"));
  }

  @Test
  @DisplayName("JS-SEC-043: an absent `aud` yields an empty set (consumers must fail closed)")
  void audAbsent() {
    assertEquals(Set.of(), OAuth2Json.stringOrArray("{\"active\":true}", "aud"));
  }
}
