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

import java.util.Map;
import java.util.Optional;

/** Helpers for working with {@link RestRequest} headers. */
public final class RestHeaders {

  /** Standard {@code WWW-Authenticate} response header name (RFC 7235). */
  public static final String WWW_AUTHENTICATE = "WWW-Authenticate";

  private RestHeaders() {
  }

  /**
   * Case-insensitive lookup of the first matching header value.
   *
   * @param request the request
   * @param name    header name
   * @return the value, or empty if absent / blank
   */
  public static Optional<String> first(RestRequest request, String name) {
    if (request == null || name == null) return Optional.empty();
    Map<String, String> headers = request.headers();
    String direct = headers.get(name);
    if (direct != null && !direct.isBlank()) return Optional.of(direct);
    for (Map.Entry<String, String> entry : headers.entrySet()) {
      if (name.equalsIgnoreCase(entry.getKey()) && entry.getValue() != null
          && !entry.getValue().isBlank()) {
        return Optional.of(entry.getValue());
      }
    }
    return Optional.empty();
  }
}
