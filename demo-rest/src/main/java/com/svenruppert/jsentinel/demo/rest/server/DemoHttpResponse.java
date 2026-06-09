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
package com.svenruppert.jsentinel.demo.rest.server;

import com.svenruppert.jsentinel.rest.RestResponse;

import java.util.LinkedHashMap;
import java.util.Map;

/** Buffering {@link RestResponse} implementation used by the demo server. */
public final class DemoHttpResponse implements RestResponse {

  private int status = 200;
  private String body = "";
  private final Map<String, String> headers = new LinkedHashMap<>();

  @Override
  public void status(int statusCode) {
    this.status = statusCode;
  }

  @Override
  public void body(String body) {
    this.body = body == null ? "" : body;
  }

  @Override
  public void header(String name, String value) {
    if (name == null || name.isBlank() || value == null) {
      return;
    }
    headers.put(name, value);
  }

  public int status() {
    return status;
  }

  public String getBody() {
    return body;
  }

  /** Read-only view of the headers set via {@link #header(String, String)}. */
  public Map<String, String> getHeaders() {
    return Map.copyOf(headers);
  }
}
