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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.rest.RestRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Objects;

/**
 * Binds the OAuth2 callback {@code state} to the user-agent that started the
 * flow (V00.81, BL01 / CWE-352). The process-global {@code JdkInMemoryStateStore}
 * only proves a {@code state} was <em>issued</em> — not that this callback comes
 * from the browser that requested it. Without a binding, any caller presenting a
 * stolen (still-unconsumed) {@code state} completes the login (login-CSRF /
 * session fixation).
 *
 * <p>{@link OAuth2CallbackHandler} evaluates the binding <em>before</em> driving
 * the flow: a non-matching callback is rejected fail-closed with a generic
 * {@code 400} and the single-use {@code state} stays unconsumed, so the
 * legitimate browser can still complete its flow.
 *
 * <p>The shipped implementation is {@link #hostCookie()}: at
 * {@code startRequest(...)} time the application emits the
 * {@code Set-Cookie} header produced by {@link #hostCookieHeader(String)}
 * alongside the redirect to the authorization endpoint; on the callback the
 * cookie value must equal the {@code state} query parameter (compared in
 * constant time). The {@code __Host-} prefix pins the cookie to this origin,
 * {@code Secure; HttpOnly; SameSite=Lax; Path=/}.
 *
 * @since 00.81.00
 */
@ExperimentalJSentinelApi
@FunctionalInterface
public interface CallbackStateBinding {

  /** Default cookie carrying the state binding. */
  String DEFAULT_COOKIE_NAME = "__Host-JSentinelOAuth2State";

  /** Cookie attributes for the binding cookie (5-minute lifetime, origin-pinned). */
  String COOKIE_ATTRIBUTES = "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300";

  /**
   * Decides whether the callback carrying {@code state} belongs to the
   * user-agent issuing {@code request}.
   *
   * @param state   the non-blank {@code state} query parameter
   * @param request the callback request
   * @return {@code true} when the callback is bound to this user-agent
   */
  boolean matches(String state, RestRequest request);

  /**
   * The {@code __Host-} cookie binding with the {@link #DEFAULT_COOKIE_NAME}.
   *
   * @return fail-closed cookie binding
   */
  static CallbackStateBinding hostCookie() {
    return hostCookie(DEFAULT_COOKIE_NAME);
  }

  /**
   * The {@code __Host-} cookie binding with a custom cookie name. The callback
   * matches only when the named cookie is present and its value equals the
   * {@code state} parameter (constant-time comparison).
   *
   * @param cookieName cookie name; must not be {@code null} or blank
   * @return fail-closed cookie binding
   */
  static CallbackStateBinding hostCookie(String cookieName) {
    Objects.requireNonNull(cookieName, "cookieName");
    if (cookieName.isBlank()) {
      throw new IllegalArgumentException("cookieName must not be blank");
    }
    return (state, request) -> {
      String cookieValue = cookieValue(request, cookieName);
      if (cookieValue == null || cookieValue.isBlank()) {
        return false;
      }
      return MessageDigest.isEqual(
          cookieValue.getBytes(StandardCharsets.UTF_8),
          state.getBytes(StandardCharsets.UTF_8));
    };
  }

  /**
   * No binding — every callback with a valid {@code state} passes. Only for
   * integrations that already bind {@code state} to the caller themselves
   * (e.g. in the {@code TokenSink} or a wrapping filter).
   *
   * @return permissive binding
   */
  static CallbackStateBinding unbound() {
    return (state, request) -> true;
  }

  /**
   * Builds the {@code Set-Cookie} header value the application emits at
   * {@code startRequest(...)} time, using the {@link #DEFAULT_COOKIE_NAME}.
   *
   * @param state the state key returned by {@code startRequest(...)}
   * @return {@code Set-Cookie} header value
   */
  static String hostCookieHeader(String state) {
    return hostCookieHeader(DEFAULT_COOKIE_NAME, state);
  }

  /**
   * Builds the {@code Set-Cookie} header value for a custom cookie name.
   * Rejects control characters in {@code state} (header-injection guard).
   *
   * @param cookieName cookie name; must not be {@code null} or blank
   * @param state      the state key returned by {@code startRequest(...)}
   * @return {@code Set-Cookie} header value
   */
  static String hostCookieHeader(String cookieName, String state) {
    Objects.requireNonNull(cookieName, "cookieName");
    Objects.requireNonNull(state, "state");
    if (cookieName.isBlank()) {
      throw new IllegalArgumentException("cookieName must not be blank");
    }
    // RF-a (exit review): the NAME feeds the Set-Cookie header too — a control
    // character or separator in it would be header injection just like in the
    // value, so both sides get the same guard.
    for (int i = 0; i < cookieName.length(); i++) {
      char c = cookieName.charAt(i);
      if (c < 0x21 || c == 0x7F || c == ';' || c == ',' || c == '=') {
        throw new IllegalArgumentException("cookieName contains characters illegal in a cookie name");
      }
    }
    for (int i = 0; i < state.length(); i++) {
      char c = state.charAt(i);
      if (c < 0x20 || c == 0x7F || c == ';' || c == ',') {
        throw new IllegalArgumentException("state contains characters illegal in a cookie value");
      }
    }
    return cookieName + "=" + state + COOKIE_ATTRIBUTES;
  }

  private static String cookieValue(RestRequest request, String cookieName) {
    String header = header(request, "Cookie");
    if (header == null) {
      return null;
    }
    String prefix = cookieName + "=";
    for (String part : header.split(";")) {
      String candidate = part.trim();
      if (candidate.startsWith(prefix)) {
        return candidate.substring(prefix.length());
      }
    }
    return null;
  }

  private static String header(RestRequest request, String name) {
    Map<String, String> headers = request.headers();
    String direct = headers.get(name);
    if (direct != null) {
      return direct;
    }
    // adapters differ in header-name casing; fall back to a case-insensitive scan
    for (Map.Entry<String, String> entry : headers.entrySet()) {
      if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
        return entry.getValue();
      }
    }
    return null;
  }
}
