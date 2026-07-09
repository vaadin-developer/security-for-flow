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
package com.svenruppert.jsentinel.oauth2;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.oauth2.api.ClientAuthentication;
import com.svenruppert.jsentinel.oauth2.api.DeviceAuthorizationClient;
import com.svenruppert.jsentinel.oauth2.api.DeviceAuthorizationResponse;
import com.svenruppert.jsentinel.oauth2.api.OAuth2Error;
import com.svenruppert.jsentinel.oauth2.internal.OAuth2FormPost;
import com.svenruppert.jsentinel.oauth2.internal.OAuth2Json;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * RFC 8628 §3.1/§3.2 device-authorization endpoint over JDK {@link HttpClient}
 * (V00.77): exchanges scopes for a {@code device_code} + {@code user_code}. The
 * absolute {@code expiresAt} is derived from {@code expires_in} against the
 * injected clock; a missing {@code interval} defaults per RFC 8628.
 */
public final class HttpDeviceAuthorizationClient implements DeviceAuthorizationClient {

  private static final String CODE = "oauth2/device-authorization-endpoint";

  private final HttpClient http;
  private final URI endpoint;
  private final ClientAuthentication clientAuthentication;
  private final Supplier<Instant> clock;

  public HttpDeviceAuthorizationClient(HttpClient http, URI endpoint,
      ClientAuthentication clientAuthentication) {
    this(http, endpoint, clientAuthentication, Instant::now);
  }

  public HttpDeviceAuthorizationClient(HttpClient http, URI endpoint,
      ClientAuthentication clientAuthentication, Supplier<Instant> clock) {
    this.http = Objects.requireNonNull(http, "http");
    this.endpoint = OAuth2FormPost.requireHttps(Objects.requireNonNull(endpoint, "endpoint"), CODE);
    this.clientAuthentication = Objects.requireNonNull(clientAuthentication, "clientAuthentication");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public Result<DeviceAuthorizationResponse, OAuth2Error> requestDeviceCode(Set<String> scopes) {
    Map<String, String> form = new LinkedHashMap<>();
    if (scopes != null && !scopes.isEmpty()) {
      form.put("scope", String.join(" ", scopes));
    }
    return OAuth2FormPost.post(http, endpoint, form, clientAuthentication).flatMap(outcome -> {
      if (outcome.status() / 100 != 2) {
        return OAuth2Json.string(outcome.body(), "error")
            .<Result<DeviceAuthorizationResponse, OAuth2Error>>map(
                e -> Result.failure(new OAuth2Error.ProtocolError(e)))
            .orElseGet(() -> Result.failure(new OAuth2Error.EndpointError(outcome.status())));
      }
      return parse(outcome.body());
    });
  }

  private Result<DeviceAuthorizationResponse, OAuth2Error> parse(String body) {
    String deviceCode = OAuth2Json.string(body, "device_code").orElse(null);
    String userCode = OAuth2Json.string(body, "user_code").orElse(null);
    String verificationUri = OAuth2Json.string(body, "verification_uri").orElse(null);
    if (deviceCode == null || userCode == null || verificationUri == null) {
      return Result.failure(new OAuth2Error.MalformedResponse(
          "device-authorization response missing device_code/user_code/verification_uri"));
    }
    long interval = OAuth2Json.longValue(body, "interval")
        .orElse(DeviceAuthorizationResponse.DEFAULT_INTERVAL_SECONDS);
    Instant expiresAt = clock.get().plusSeconds(
        OAuth2Json.longValue(body, "expires_in").orElse(600L));
    return Result.success(new DeviceAuthorizationResponse(
        deviceCode, userCode, URI.create(verificationUri),
        OAuth2Json.string(body, "verification_uri_complete").map(URI::create),
        expiresAt, interval));
  }
}
