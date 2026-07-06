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
package com.svenruppert.jsentinel.rest;

import com.svenruppert.jsentinel.audit.LogFieldScrubber;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Creates neutral access contexts from REST requests.
 */
public final class RestAccessContextFactory {

  /**
   * Creates an access context from a REST request.
   *
   * @param request    request
   * @param subject    authenticated subject
   * @param operation  operation name
   * @param attributes additional attributes
   * @return access context
   */
  public AccessContext create(
      RestRequest request,
      Optional<JSentinelSubject> subject,
      String operation,
      Map<String, Object> attributes) {
    Map<String, Object> contextAttributes = new LinkedHashMap<>(
        attributes == null ? Map.of() : attributes);
    // JS-SEC-031 (CWE-117): the request path is attacker-controlled and flows into the
    // audit route (and any consumer of resourceName). Neutralize CR/LF/control chars AND the
    // space delimiter at the adapter boundary (JS-SEC-045: the shared LogFieldScrubber, so this
    // adapter cannot drift from the audit sink) so it cannot forge a downstream log line or field.
    String safePath = LogFieldScrubber.scrub(request.path());
    contextAttributes.put("method", request.method());
    contextAttributes.put("path", safePath);
    contextAttributes.put("queryParameters", Map.copyOf(request.queryParameters()));
    return new AccessContext(
        subject,
        "rest-endpoint",
        safePath,
        operation,
        contextAttributes);
  }

}
