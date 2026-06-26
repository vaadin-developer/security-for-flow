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
package com.svenruppert.jsentinel.oauth2.rest;

/*-
 * #%L
 * jSentinel OAuth2 — REST callback adapter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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
import com.svenruppert.jsentinel.oauth2.api.AuthorizationCodeFlow;
import com.svenruppert.jsentinel.oauth2.api.OAuth2Error;
import com.svenruppert.jsentinel.oauth2.api.TokenResponse;
import com.svenruppert.jsentinel.rest.RestHandler;
import com.svenruppert.jsentinel.rest.RestRequest;
import com.svenruppert.jsentinel.rest.RestResponse;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The REST-side OAuth2 redirect-callback handler (V00.77). Reads {@code code} +
 * {@code state} (or {@code error}) from the callback query string, drives the
 * {@link AuthorizationCodeFlow} (single-use state validation + PKCE code
 * exchange) and hands the resulting tokens to a consumer-supplied
 * {@link TokenSink} — the handler itself never writes tokens into the response
 * body. Errors map to short, generic statuses + bodies; the OAuth
 * {@code error_description} is never echoed (no internals leak to the caller).
 */
public final class OAuth2CallbackHandler implements RestHandler {

  /** Receives the obtained tokens (e.g. binds them into a session / store). */
  @FunctionalInterface
  public interface TokenSink {
    void accept(TokenResponse tokens, RestRequest request);
  }

  private final AuthorizationCodeFlow flow;
  private final TokenSink tokenSink;

  public OAuth2CallbackHandler(AuthorizationCodeFlow flow, TokenSink tokenSink) {
    this.flow = Objects.requireNonNull(flow, "flow");
    this.tokenSink = Objects.requireNonNull(tokenSink, "tokenSink");
  }

  @Override
  public void handle(RestRequest request, RestResponse response) {
    Map<String, String> query = request.queryParameters();
    String state = query.get("state");
    if (state == null || state.isBlank()) {
      response.status(400);
      response.body("Invalid callback");
      return;
    }
    AuthorizationCodeFlow.CallbackParams params = new AuthorizationCodeFlow.CallbackParams(
        opt(query.get("code")), state, opt(query.get("error")), opt(query.get("error_description")));

    Result<TokenResponse, OAuth2Error> result = flow.handleCallback(params);
    if (result.isSuccess()) {
      tokenSink.accept(result.toOptional().orElseThrow(), request);
      response.status(204);
      return;
    }
    OAuth2Error error = result.fold(ok -> (OAuth2Error) null, e -> e);
    response.status(statusFor(error));
    response.body(messageFor(error));
  }

  private static Optional<String> opt(String value) {
    return (value == null || value.isBlank()) ? Optional.empty() : Optional.of(value);
  }

  private static int statusFor(OAuth2Error error) {
    return switch (error) {
      case OAuth2Error.AuthorizationDenied ignored -> 403;
      case OAuth2Error.NetworkError ignored -> 502;
      case OAuth2Error.EndpointError ignored -> 502;
      default -> 400; // StateInvalid / ProtocolError / Malformed / ... → bad request
    };
  }

  private static String messageFor(OAuth2Error error) {
    return switch (error) {
      case OAuth2Error.AuthorizationDenied ignored -> "Authorization denied";
      case OAuth2Error.StateInvalid ignored -> "Invalid state";
      default -> "OAuth2 callback failed"; // never echoes error_description
    };
  }
}
