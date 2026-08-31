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
package eu.jsentinel.jcustos.oauth2.rest;

/*-
 * #%L
 * jCustos OAuth2 — REST callback adapter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow;
import eu.jsentinel.jcustos.oauth2.api.CallbackResult;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.rest.RestHandler;
import eu.jsentinel.jcustos.rest.RestRequest;
import eu.jsentinel.jcustos.rest.RestResponse;

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
 *
 * <p><strong>Security — bind {@code state} to the user-agent (login-CSRF).</strong>
 * REST has no inherent per-browser store, so the default
 * {@code JdkInMemoryStateStore} is process-global: validating only that a
 * {@code state} exists does <em>not</em> prove the callback belongs to the
 * browser that started the flow. Since V00.81 (BL01, CWE-352) the handler
 * enforces this fail-closed through a {@link CallbackStateBinding} evaluated
 * <em>before</em> the flow runs — a non-matching callback is a generic
 * {@code 400} and the single-use {@code state} stays unconsumed. Use
 * {@link CallbackStateBinding#hostCookie()} together with
 * {@link CallbackStateBinding#hostCookieHeader(String)} on the start side.
 * The two-argument constructor keeps the pre-V00.81 unbound behavior for
 * integrations that bind state themselves (e.g. in the {@link TokenSink}) and
 * logs the open login-CSRF surface once at construction
 * ({@code oauth2/state-unbound}). The Vaadin adapter's
 * {@code VaadinSessionStateStore} already binds state to the
 * {@code VaadinSession} and needs no extra step.
 */
public final class OAuth2CallbackHandler implements RestHandler, HasLogger {

  /**
   * Receives the callback outcome (e.g. binds the tokens into a session / store). JS-SEC-059: the
   * argument is a {@link CallbackResult} — {@code result.tokens()} plus the stored {@code nonce()}
   * and {@code resumeTarget()} — so a sink that validates the {@code id_token} can enforce the
   * nonce via {@code IdTokenExpectations.of(issuer, audience, result.nonce())}.
   */
  @FunctionalInterface
  public interface TokenSink {
    void accept(CallbackResult result, RestRequest request);
  }

  static final String INVALID_CALLBACK_BODY = "Invalid callback";

  private final AuthorizationCodeFlow flow;
  private final TokenSink tokenSink;
  private final CallbackStateBinding stateBinding;

  /**
   * Pre-V00.81 constructor — no user-agent binding. Only for integrations that
   * bind {@code state} to the caller themselves; logs the open login-CSRF
   * surface once at construction.
   *
   * @param flow      the authorization-code flow
   * @param tokenSink receives the callback outcome
   */
  public OAuth2CallbackHandler(AuthorizationCodeFlow flow, TokenSink tokenSink) {
    this(flow, tokenSink, CallbackStateBinding.unbound());
    logger().warn("oauth2/state-unbound: callback state is not bound to the user-agent — "
        + "any caller presenting a valid state completes the login (login-CSRF surface). "
        + "Pass CallbackStateBinding.hostCookie() and emit "
        + "CallbackStateBinding.hostCookieHeader(state) at startRequest(...) time, "
        + "or keep binding state yourself in the TokenSink.");
  }

  /**
   * @param flow         the authorization-code flow
   * @param tokenSink    receives the callback outcome
   * @param stateBinding binds the callback to the user-agent that started the
   *                     flow; evaluated fail-closed before the flow runs
   * @since 00.81.00
   */
  public OAuth2CallbackHandler(AuthorizationCodeFlow flow, TokenSink tokenSink,
                               CallbackStateBinding stateBinding) {
    this.flow = Objects.requireNonNull(flow, "flow");
    this.tokenSink = Objects.requireNonNull(tokenSink, "tokenSink");
    this.stateBinding = Objects.requireNonNull(stateBinding, "stateBinding");
  }

  @Override
  public void handle(RestRequest request, RestResponse response) {
    Map<String, String> query = request.queryParameters();
    String state = query.get("state");
    if (state == null || state.isBlank()) {
      response.status(HttpStatus.BAD_REQUEST.code());
      response.body(INVALID_CALLBACK_BODY);
      return;
    }
    // BL01 (CWE-352): reject an unbound callback BEFORE driving the flow — the
    // single-use state stays unconsumed, so the legitimate browser still wins.
    if (!stateBinding.matches(state, request)) {
      response.status(HttpStatus.BAD_REQUEST.code());
      response.body(INVALID_CALLBACK_BODY);
      return;
    }
    AuthorizationCodeFlow.CallbackParams params = new AuthorizationCodeFlow.CallbackParams(
        opt(query.get("code")), state, opt(query.get("error")), opt(query.get("error_description")));

    Result<CallbackResult, OAuth2Error> result = flow.handleCallback(params);
    if (result.isSuccess()) {
      tokenSink.accept(result.toOptional().orElseThrow(), request);
      response.status(HttpStatus.NO_CONTENT.code());
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
      case OAuth2Error.AuthorizationDenied ignored -> HttpStatus.FORBIDDEN.code();
      case OAuth2Error.NetworkError ignored -> HttpStatus.BAD_GATEWAY.code();
      case OAuth2Error.EndpointError ignored -> HttpStatus.BAD_GATEWAY.code();
      // StateInvalid / ProtocolError / Malformed / ... → bad request
      default -> HttpStatus.BAD_REQUEST.code();
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
