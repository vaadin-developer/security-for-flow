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
package eu.jsentinel.jcustos.rest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("RestAuthorizationFilter.operationOf — null + locale safety (R006)")
class RestAuthorizationFilterOperationTest {

  private record SimpleRequest(
      String method, String path,
      Map<String, String> headers, Map<String, String> queryParameters
  ) implements RestRequest {
  }

  private static SimpleRequest withMethod(String method) {
    return new SimpleRequest(method, "/api/x", Map.of(), Map.of());
  }

  @Test
  @DisplayName("a null method yields an empty operation instead of an NPE")
  void nullMethodYieldsEmptyOperation() {
    assertDoesNotThrow(() -> RestAuthorizationFilter.operationOf(withMethod(null)));
    assertEquals("", RestAuthorizationFilter.operationOf(withMethod(null)));
  }

  @Test
  @DisplayName("the method is lowercased with Locale.ROOT, not the JVM default (Turkish-I)")
  void lowercasesWithRootLocaleNotDefault() {
    Locale previous = Locale.getDefault();
    try {
      Locale.setDefault(Locale.forLanguageTag("tr"));
      // Under tr_TR, "I".toLowerCase() would be "ı" (dotless i). Locale.ROOT must
      // keep it "i" so the operation token is stable across JVM locales.
      assertEquals("i", RestAuthorizationFilter.operationOf(withMethod("I")));
      assertEquals("get", RestAuthorizationFilter.operationOf(withMethod("GET")));
    } finally {
      Locale.setDefault(previous);
    }
  }
}
