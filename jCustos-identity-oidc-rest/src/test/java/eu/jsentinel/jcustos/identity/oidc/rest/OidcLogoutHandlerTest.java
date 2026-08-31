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
package eu.jsentinel.jcustos.identity.oidc.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OidcLogoutHandler (REST) — 302 redirect to the end_session endpoint")
class OidcLogoutHandlerTest {

  private static RestRequest request() {
    return new RestRequest() {
      @Override public String method() {
        return "GET";
      }

      @Override public String path() {
        return "/logout";
      }

      @Override public Map<String, String> headers() {
        return Map.of();
      }

      @Override public Map<String, String> queryParameters() {
        return Map.of();
      }
    };
  }

  private static final class CapturingResponse implements RestResponse {
    int status;
    final Map<String, String> headers = new HashMap<>();
    String body;

    @Override public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override public void body(String value) {
      this.body = value;
    }

    @Override public void header(String name, String value) {
      headers.put(name, value);
    }
  }

  @Test
  @DisplayName("redirects to the end_session URL with id_token_hint + post_logout_redirect_uri")
  void redirectsToEndSession() {
    OidcLogoutHandler handler = new OidcLogoutHandler(
        URI.create("https://idp.example/logout"),
        OidcLogoutHandler.hintFrom(req -> "ID-TOKEN", URI.create("https://app.example/")));
    CapturingResponse response = new CapturingResponse();
    handler.handle(request(), response);

    assertEquals(302, response.status);
    String location = response.headers.get("Location");
    assertTrue(location.startsWith("https://idp.example/logout?"), location);
    assertTrue(location.contains("id_token_hint=ID-TOKEN"), location);
    assertTrue(location.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example%2F"), location);
  }
}
