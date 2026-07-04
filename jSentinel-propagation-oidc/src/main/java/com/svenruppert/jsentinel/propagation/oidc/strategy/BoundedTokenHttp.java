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
package com.svenruppert.jsentinel.propagation.oidc.strategy;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

/**
 * JS-SEC-036 (CWE-770): sends a token-endpoint request and reads the response body
 * bounded to {@link #MAX_BODY_BYTES}. The token-propagation strategies previously used
 * {@code BodyHandlers.ofString()}, which buffers the whole response into memory before
 * any inspection — a compromised/misbehaving OP token endpoint (or a TLS-terminating
 * proxy) could return a multi-gigabyte body and OOM the resource server. This reads via
 * {@code ofInputStream()} + {@code readNBytes(MAX + 1)} and rejects an oversized body
 * before it is fully materialized, matching the 1 MiB ceiling used by every other
 * OIDC/OAuth2 HTTP client. The returned {@link Response} mirrors {@code HttpResponse}'s
 * {@code statusCode()} / {@code body()} accessors so callers stay unchanged.
 */
final class BoundedTokenHttp {

  /** Cap on a token-endpoint response body (1 MiB). */
  static final int MAX_BODY_BYTES = 1 << 20;

  private BoundedTokenHttp() {
  }

  /** Sends {@code request} and reads the body bounded to {@link #MAX_BODY_BYTES}. */
  static Response send(HttpClient http, HttpRequest request) {
    HttpResponse<InputStream> response;
    try {
      response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
    } catch (Exception e) {
      throw new JSentinelPropagationException(0,
          "Token endpoint call failed: " + e.getMessage(), e);
    }
    try (InputStream in = response.body()) {
      byte[] bytes = in.readNBytes(MAX_BODY_BYTES + 1);
      if (bytes.length > MAX_BODY_BYTES) {
        throw new JSentinelPropagationException(response.statusCode(),
            "Token endpoint response exceeds " + MAX_BODY_BYTES + " bytes");
      }
      return new Response(response.statusCode(), new String(bytes, StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new JSentinelPropagationException(response.statusCode(),
          "Token endpoint response read failed: " + e.getMessage(), e);
    }
  }

  /** Status + fully-read (bounded) body, mirroring {@code HttpResponse} accessors. */
  record Response(int statusCode, String body) {
  }
}
