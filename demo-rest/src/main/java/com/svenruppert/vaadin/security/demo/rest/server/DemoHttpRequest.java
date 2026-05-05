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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.rest.RestRequest;

import java.util.Map;

/**
 * Demo {@link RestRequest} implementation that also carries the request body.
 */
public final class DemoHttpRequest implements RestRequest {

  private final String method;
  private final String path;
  private final Map<String, String> headers;
  private final Map<String, String> queryParameters;
  private final String body;

  public DemoHttpRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters,
      String body) {
    this.method = method;
    this.path = path;
    this.headers = Map.copyOf(headers);
    this.queryParameters = Map.copyOf(queryParameters);
    this.body = body;
  }

  @Override
  public String method() {
    return method;
  }

  @Override
  public String path() {
    return path;
  }

  @Override
  public Map<String, String> headers() {
    return headers;
  }

  @Override
  public Map<String, String> queryParameters() {
    return queryParameters;
  }

  public String body() {
    return body;
  }
}
