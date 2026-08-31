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

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RestAuthenticationFilter")
class RestAuthenticationFilterTest {

  private static final RestRequest REQUEST = new RestRequest() {
    @Override public String method() { return "GET"; }
    @Override public String path() { return "/x"; }
    @Override public Map<String, String> headers() { return Map.of(); }
    @Override public Map<String, String> queryParameters() { return Map.of(); }
  };

  @Test
  @DisplayName("returns 401 with body 'Unauthorized' when no subject is resolved")
  void unauthenticated() {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean called = new AtomicBoolean();
    new RestAuthenticationFilter(req -> Optional.empty())
        .requireAuthenticated(REQUEST, response, (r, w) -> called.set(true));
    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
    assertFalse(called.get());
  }

  @Test
  @DisplayName("delegates to the handler when a subject is present")
  void authenticated() {
    RecordingResponse response = new RecordingResponse();
    AtomicBoolean called = new AtomicBoolean();
    JSentinelSubject subject = new JSentinelSubject("u", "User", Set.of(), Set.of());
    new RestAuthenticationFilter(req -> Optional.of(subject))
        .requireAuthenticated(REQUEST, response, (r, w) -> {
          called.set(true);
          w.status(204);
        });
    assertEquals(204, response.status);
    assertTrue(called.get());
  }

  static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;
    @Override public void status(int code) { status = code; }
    @Override public void body(String body) { this.body = body; }
  }
}
