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

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RestAccessContextFactoryTest {

  private final RestAccessContextFactory factory = new RestAccessContextFactory();

  private record SimpleRequest(
      String method, String path,
      Map<String, String> headers, Map<String, String> queryParameters
  ) implements RestRequest {
  }

  private static SimpleRequest req() {
    return new SimpleRequest("GET", "/api/x", Map.of(), Map.of("q", "1"));
  }

  @Test
  @DisplayName("JS-SEC-031: CR/LF in the request path is scrubbed from resourceName and the path attribute")
  void scrubsCrlfInPath() {
    SimpleRequest r = new SimpleRequest(
        "GET", "/api/x\r\nAUDIT type=LoginSucceeded user=admin", Map.of(), Map.of());

    AccessContext ctx = factory.create(r, Optional.empty(), "read", Map.of());

    assertFalse(ctx.resourceName().contains("\n"), ctx.resourceName());
    assertFalse(ctx.resourceName().contains("\r"), ctx.resourceName());
    assertFalse(((String) ctx.attributes().get("path")).contains("\n"),
        (String) ctx.attributes().get("path"));
  }

  @Test
  @DisplayName("create() builds rest-endpoint context with method/path/queryParameters attributes")
  void buildsRestContext() {
    AccessContext ctx = factory.create(req(), Optional.empty(), "read", Map.of());

    assertEquals("rest-endpoint", ctx.resourceType());
    assertEquals("/api/x", ctx.resourceName());
    assertEquals("read", ctx.operation());
    assertEquals("GET", ctx.attributes().get("method"));
    assertEquals("/api/x", ctx.attributes().get("path"));
    assertEquals(Map.of("q", "1"), ctx.attributes().get("queryParameters"));
  }

  @Test
  @DisplayName("subject Optional is forwarded to the context as-is")
  void subjectIsForwarded() {
    JCustosSubject subject = new JCustosSubject("u1", "User", Set.of(), Set.of());

    AccessContext ctx = factory.create(req(), Optional.of(subject), "read", Map.of());

    assertTrue(ctx.subject().isPresent());
    assertSame(subject, ctx.subject().get());
  }

  @Test
  @DisplayName("a null attributes map is tolerated and yields method/path/queryParameters only")
  void nullAttributesAreTolerated() {
    AccessContext ctx = factory.create(req(), Optional.empty(), "read", null);

    assertEquals("GET", ctx.attributes().get("method"));
    assertEquals("/api/x", ctx.attributes().get("path"));
    assertEquals(Map.of("q", "1"), ctx.attributes().get("queryParameters"));
    assertEquals(3, ctx.attributes().size(),
        "with null caller-supplied attributes, only the three rest fields should be present");
  }

  @Test
  @DisplayName("caller-supplied attributes are preserved and not overwritten unless they collide")
  void preservesCallerAttributes() {
    Map<String, Object> caller = new LinkedHashMap<>();
    caller.put("operation-id", "op-42");
    caller.put("custom", true);

    AccessContext ctx = factory.create(req(), Optional.empty(), "read", caller);

    assertEquals("op-42", ctx.attributes().get("operation-id"));
    assertEquals(true, ctx.attributes().get("custom"));
    assertEquals("GET", ctx.attributes().get("method"));
    assertEquals("/api/x", ctx.attributes().get("path"));
  }

  @Test
  @DisplayName("queryParameters in attributes is a defensive copy, independent of the request map")
  void queryParametersAreCopied() {
    Map<String, String> mutableQp = new LinkedHashMap<>();
    mutableQp.put("q", "first");
    SimpleRequest request = new SimpleRequest("GET", "/api/x", Map.of(), mutableQp);

    AccessContext ctx = factory.create(request, Optional.empty(), "read", Map.of());

    @SuppressWarnings("unchecked")
    Map<String, String> stored = (Map<String, String>) ctx.attributes().get("queryParameters");
    assertEquals("first", stored.get("q"));

    mutableQp.put("q", "second");
    assertEquals("first", stored.get("q"),
        "later mutations of the request query map must not leak into the context");
    assertThrows(UnsupportedOperationException.class, () -> stored.put("k", "v"));
  }

  @Test
  @DisplayName("context.attributes() is unmodifiable")
  void attributesAreUnmodifiable() {
    AccessContext ctx = factory.create(req(), Optional.empty(), "read",
        Map.of("k", "v"));

    assertThrows(UnsupportedOperationException.class,
        () -> ctx.attributes().put("evil", "value"));
  }
}
