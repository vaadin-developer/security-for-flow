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
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.oauth2.api.OAuth2ClientConfig;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.PkceChallenge;
import eu.jsentinel.jcustos.oauth2.api.PkceVerifier;
import eu.jsentinel.jcustos.oauth2.api.StateEntry;
import eu.jsentinel.jcustos.oauth2.api.StateStore;
import eu.jsentinel.jcustos.oauth2.api.TokenEndpointClient;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The {@link AuthorizationCodeFlow} HTTP implementation (V00.77). Generates a
 * high-entropy single-use {@code state} and a PKCE (S256) verifier, binds them
 * in the {@link StateStore}, and builds the authorization redirect; on the
 * callback it consumes the state single-use and exchanges the code (with the
 * stored verifier) via the {@link TokenEndpointClient}.
 *
 * @since 00.77.00
 */
@ExperimentalJCustosApi
public final class HttpAuthorizationCodeFlow implements AuthorizationCodeFlow {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

  private final OAuth2ClientConfig config;
  private final TokenEndpointClient tokenEndpoint;
  private final StateStore stateStore;
  private final Supplier<Instant> clock;

  public HttpAuthorizationCodeFlow(OAuth2ClientConfig config, TokenEndpointClient tokenEndpoint,
      StateStore stateStore) {
    this(config, tokenEndpoint, stateStore, Instant::now);
  }

  public HttpAuthorizationCodeFlow(OAuth2ClientConfig config, TokenEndpointClient tokenEndpoint,
      StateStore stateStore, Supplier<Instant> clock) {
    this.config = Objects.requireNonNull(config, "config");
    this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
    this.stateStore = Objects.requireNonNull(stateStore, "stateStore");
    this.clock = Objects.requireNonNull(clock, "clock");
    if (config.authorizationEndpoint().isEmpty()) {
      throw new IllegalStateException("oauth2/missing-authorization-endpoint");
    }
    if (config.redirectUri().isEmpty()) {
      throw new IllegalStateException("oauth2/missing-redirect-uri");
    }
  }

  @Override
  public AuthorizationRequest startRequest(StartRequestParams params) {
    Objects.requireNonNull(params, "params");
    String state = randomToken();
    PkceVerifier verifier = PkceVerifier.generate();
    PkceChallenge challenge = verifier.challenge();

    stateStore.bind(state,
        new StateEntry(verifier.value(), params.nonce(), params.resumeTarget(), Map.of(), clock.get()),
        config.stateTtl());

    Set<String> scopes = new LinkedHashSet<>(config.scopes());
    scopes.addAll(params.additionalScopes());

    StringBuilder query = new StringBuilder();
    append(query, "response_type", "code");
    append(query, "client_id", config.clientId());
    append(query, "redirect_uri", config.redirectUri().orElseThrow().toString());
    if (!scopes.isEmpty()) {
      append(query, "scope", String.join(" ", scopes));
    }
    append(query, "state", state);
    append(query, "code_challenge", challenge.codeChallenge());
    append(query, "code_challenge_method", challenge.method());
    params.nonce().ifPresent(n -> append(query, "nonce", n));
    for (Map.Entry<String, String> e : params.additionalParams().entrySet()) {
      append(query, e.getKey(), e.getValue());
    }

    URI authEndpoint = config.authorizationEndpoint().orElseThrow();
    String sep = authEndpoint.getRawQuery() == null ? "?" : "&";
    return new AuthorizationRequest(URI.create(authEndpoint + sep + query), state);
  }

  @Override
  public Result<CallbackResult, OAuth2Error> handleCallback(CallbackParams params) {
    Objects.requireNonNull(params, "params");
    if (params.error().isPresent()) {
      return Result.failure(new OAuth2Error.AuthorizationDenied(params.error().get()));
    }
    var entry = stateStore.consume(params.state());
    if (entry.isEmpty()) {
      return Result.failure(new OAuth2Error.StateInvalid("unknown, consumed, or expired state"));
    }
    if (params.code().isEmpty()) {
      return Result.failure(new OAuth2Error.StateInvalid("callback carried neither code nor error"));
    }
    // JS-SEC-059: the single-use state was just consumed, so this is the only point the stored
    // nonce + resumeTarget can be recovered — surface them alongside the tokens so the caller can
    // bind the id_token to the nonce (IdTokenExpectations.of(iss, aud, nonce)).
    StateEntry state = entry.get();
    return tokenEndpoint.exchangeCode(
            params.code().get(),
            config.redirectUri().orElseThrow(),
            PkceVerifier.of(state.pkceVerifier()))
        .map(tokens -> new CallbackResult(tokens, state.nonce(), state.resumeTarget()));
  }

  private static String randomToken() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return B64URL.encodeToString(bytes);
  }

  private static void append(StringBuilder query, String key, String value) {
    if (query.length() > 0) {
      query.append('&');
    }
    query.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
        .append('=')
        .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
  }
}
