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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl5
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.PkceVerifier;
import eu.jsentinel.jcustos.oauth2.api.TokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;
import eu.jsentinel.jcustos.oauth2.internal.ClientAssertions;
import eu.jsentinel.jcustos.oauth2.internal.JwtSigners;
import eu.jsentinel.jcustos.oauth2.internal.OAuth2Json;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * JDK-HttpClient {@link TokenEndpointClient} (V00.77). POSTs the form-encoded
 * grant to the token endpoint, applies the configured client authentication
 * (Basic header / body fields / public client) and maps the response to a
 * {@link TokenResponse} or a non-secret {@link OAuth2Error}.
 *
 * <p>Discipline: HTTPS is enforced (loopback {@code http} only with
 * {@code -Djcustos.dev=true}); the response body is capped at 1 MiB and read
 * via the depth-aware {@link OAuth2Json} scanner; a missing {@code access_token}
 * on a 2xx is a {@code malformed-response}; a 4xx with an {@code error} field is
 * a {@code protocol-error}; any other non-2xx is an {@code endpoint-error}.
 *
 * <p>Signed client assertions ({@code private_key_jwt} / {@code client_secret_jwt})
 * are wired in V00.77 phase 6.
 *
 * @since 00.77.00
 */
@ExperimentalJCustosApi
public final class HttpTokenEndpointClient implements TokenEndpointClient {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);
  private static final int MAX_BYTES = 1024 * 1024;
  private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

  private final URI tokenEndpoint;
  private final ClientAuthentication clientAuth;
  private final HttpClient http;
  private final Supplier<Instant> clock;

  public HttpTokenEndpointClient(URI tokenEndpoint, ClientAuthentication clientAuth, HttpClient http) {
    this(tokenEndpoint, clientAuth, http, Instant::now);
  }

  public HttpTokenEndpointClient(URI tokenEndpoint, ClientAuthentication clientAuth,
      HttpClient http, Supplier<Instant> clock) {
    this.tokenEndpoint = requireHttps(Objects.requireNonNull(tokenEndpoint, "tokenEndpoint"));
    this.clientAuth = Objects.requireNonNull(clientAuth, "clientAuth");
    this.http = Objects.requireNonNull(http, "http");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public Result<TokenResponse, OAuth2Error> exchangeCode(String code, URI redirectUri, PkceVerifier pkce) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "authorization_code");
    form.put("code", Objects.requireNonNull(code, "code"));
    form.put("redirect_uri", Objects.requireNonNull(redirectUri, "redirectUri").toString());
    form.put("code_verifier", Objects.requireNonNull(pkce, "pkce").value());
    return post(form);
  }

  @Override
  public Result<TokenResponse, OAuth2Error> refresh(SecretValue refreshToken) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "refresh_token");
    byte[] rt = refreshToken.asUtf8Bytes();
    form.put("refresh_token", new String(rt, StandardCharsets.UTF_8));
    Arrays.fill(rt, (byte) 0);
    return post(form);
  }

  @Override
  public Result<TokenResponse, OAuth2Error> clientCredentials(Set<String> scopes) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "client_credentials");
    if (scopes != null && !scopes.isEmpty()) {
      form.put("scope", String.join(" ", scopes));
    }
    return post(form);
  }

  @Override
  public Result<TokenResponse, OAuth2Error> deviceToken(String deviceCode) {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", DEVICE_CODE_GRANT);
    form.put("device_code", Objects.requireNonNull(deviceCode, "deviceCode"));
    return post(form);
  }

  private Result<TokenResponse, OAuth2Error> post(Map<String, String> form) {
    HttpRequest.Builder request = HttpRequest.newBuilder(tokenEndpoint)
        .timeout(TIMEOUT)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded");
    applyClientAuth(form, request);

    HttpResponse<InputStream> response;
    try {
      response = http.send(request.POST(HttpRequest.BodyPublishers.ofString(encode(form))).build(),
          HttpResponse.BodyHandlers.ofInputStream());
    } catch (java.net.http.HttpTimeoutException e) {
      return Result.failure(new OAuth2Error.NetworkError("timeout"));
    } catch (IOException e) {
      return Result.failure(new OAuth2Error.NetworkError(e.getClass().getSimpleName()));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Result.failure(new OAuth2Error.NetworkError("interrupted"));
    }

    String body;
    try (InputStream in = response.body()) {
      byte[] bytes = in.readNBytes(MAX_BYTES + 1);
      if (bytes.length > MAX_BYTES) {
        return Result.failure(new OAuth2Error.MalformedResponse("body exceeds the size cap"));
      }
      body = new String(bytes, StandardCharsets.UTF_8);
    } catch (IOException e) {
      return Result.failure(new OAuth2Error.NetworkError(e.getClass().getSimpleName()));
    }

    int status = response.statusCode();
    if (status / 100 == 2) {
      return parseTokenResponse(body);
    }
    // RFC 6749 §5.2: a 4xx error body carries an "error" field
    Optional<String> oauthError = OAuth2Json.string(body, "error");
    return oauthError.<Result<TokenResponse, OAuth2Error>>map(
            e -> Result.failure(new OAuth2Error.ProtocolError(e)))
        .orElseGet(() -> Result.failure(new OAuth2Error.EndpointError(status)));
  }

  private Result<TokenResponse, OAuth2Error> parseTokenResponse(String body) {
    Optional<String> accessToken = OAuth2Json.string(body, "access_token");
    if (accessToken.isEmpty()) {
      return Result.failure(new OAuth2Error.MalformedResponse("no access_token"));
    }
    String tokenType = OAuth2Json.string(body, "token_type").orElse("Bearer");
    Optional<Instant> expiresAt = OAuth2Json.longValue(body, "expires_in")
        .map(seconds -> clock.get().plusSeconds(seconds));
    Optional<String> refreshToken = OAuth2Json.string(body, "refresh_token");
    Optional<String> idToken = OAuth2Json.string(body, "id_token");
    Set<String> scopes = OAuth2Json.string(body, "scope")
        .map(OAuth2Json::parseScopes)
        .orElse(Set.of());
    return Result.success(new TokenResponse(
        accessToken.get(), refreshToken, idToken, tokenType, expiresAt, scopes));
  }

  private void applyClientAuth(Map<String, String> form, HttpRequest.Builder request) {
    switch (clientAuth) {
      case ClientAuthentication.ClientSecretBasic basic ->
          request.header("Authorization", basicHeader(basic.clientId(), basic.secret()));
      case ClientAuthentication.ClientSecretPost post -> {
        form.put("client_id", post.clientId());
        byte[] secret = post.secret().asUtf8Bytes();
        form.put("client_secret", new String(secret, StandardCharsets.UTF_8));
        Arrays.fill(secret, (byte) 0);
      }
      case ClientAuthentication.NoneAuthentication none -> form.put("client_id", none.clientId());
      case ClientAuthentication.PrivateKeyJwt pk ->
          ClientAssertions.applyPrivateKeyJwt(pk, tokenEndpoint, clock, JwtSigners.require(), form);
      case ClientAuthentication.ClientSecretJwt cs ->
          ClientAssertions.applyClientSecretJwt(cs, tokenEndpoint, clock, form);
    }
  }

  private static String basicHeader(String clientId, SecretValue secret) {
    byte[] secretBytes = secret.asUtf8Bytes();
    byte[] idBytes = clientId.getBytes(StandardCharsets.UTF_8);
    byte[] userInfo = new byte[idBytes.length + 1 + secretBytes.length];
    System.arraycopy(idBytes, 0, userInfo, 0, idBytes.length);
    userInfo[idBytes.length] = ':';
    System.arraycopy(secretBytes, 0, userInfo, idBytes.length + 1, secretBytes.length);
    String header = "Basic " + Base64.getEncoder().encodeToString(userInfo);
    java.util.Arrays.fill(userInfo, (byte) 0);
    java.util.Arrays.fill(secretBytes, (byte) 0);
    return header;
  }

  private static String encode(Map<String, String> form) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> e : form.entrySet()) {
      if (sb.length() > 0) {
        sb.append('&');
      }
      sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
          .append('=')
          .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
    }
    return sb.toString();
  }

  private static URI requireHttps(URI endpoint) {
    String scheme = endpoint.getScheme();
    if ("https".equalsIgnoreCase(scheme)) {
      return endpoint;
    }
    boolean devLoopback = Boolean.getBoolean("jcustos.dev")
        && "http".equalsIgnoreCase(scheme)
        && ("localhost".equalsIgnoreCase(endpoint.getHost()) || "127.0.0.1".equals(endpoint.getHost()));
    if (devLoopback) {
      return endpoint;
    }
    throw new IllegalArgumentException(
        "oauth2/token-endpoint-not-https: the token endpoint must use https:// (got: " + endpoint + ")");
  }
}
