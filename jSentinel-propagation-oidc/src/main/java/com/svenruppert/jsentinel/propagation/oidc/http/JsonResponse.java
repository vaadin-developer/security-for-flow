/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.propagation.oidc.http;

import java.util.Optional;

/**
 * Minimal JSON extractor for the Token-Endpoint response shape
 * {@code { "access_token": "...", "token_type": "Bearer",
 * "expires_in": 3600 }}. Avoids pulling in a third-party JSON library
 * — the V00.74 contract limits the parsed surface to these three
 * fields.
 *
 * <p>R09 (V00.76.10): extraction is scoped to the <strong>top-level</strong>
 * fields of the outermost JSON object. A previous version used a free,
 * non-anchored regex that would grab an {@code "access_token"} appearing
 * anywhere — including nested inside another object or an error description.
 * The depth-aware scanner below only matches a key that is a direct member of
 * the outermost object, so a nested field can never be picked.
 *
 * @since 00.74.00
 */
public final class JsonResponse {

  private JsonResponse() {
    throw new AssertionError("no instances");
  }

  /**
   * @return the top-level {@code access_token} value or empty if absent /
   *         malformed
   */
  public static Optional<String> accessToken(String body) {
    return topLevelValue(body, "access_token", true);
  }

  /**
   * @return the top-level {@code expires_in} value in seconds, or empty if
   *     absent or malformed. A digit run longer than {@code long} would
   *     otherwise overflow {@link Long#parseLong}; that is treated as "no usable
   *     value" rather than propagating a {@link NumberFormatException} to the
   *     caller (V00.75.10, H4).
   */
  public static Optional<Long> expiresIn(String body) {
    return topLevelValue(body, "expires_in", false).flatMap(token -> {
      try {
        return Optional.of(Long.parseLong(token));
      } catch (NumberFormatException overflow) {
        return Optional.empty();
      }
    });
  }

  /**
   * @return the top-level {@code token_type} value (typically {@code "Bearer"})
   */
  public static Optional<String> tokenType(String body) {
    return topLevelValue(body, "token_type", true);
  }

  /**
   * Extracts the value of {@code key} when it is a direct member of the
   * outermost JSON object. Tracks nesting depth and string literals (honouring
   * {@code \\} escapes) so keys inside nested objects/arrays — or strings that
   * merely contain the key text — are never matched.
   *
   * @param body       the JSON body
   * @param key        the field name to extract
   * @param wantString {@code true} for a string value, {@code false} for a
   *                   numeric/literal token
   * @return the raw value (string content, or the numeric token), or empty
   */
  private static Optional<String> topLevelValue(String body, String key, boolean wantString) {
    if (body == null) {
      return Optional.empty();
    }
    int n = body.length();
    int i = body.indexOf('{');
    if (i < 0) {
      return Optional.empty();
    }
    i++;            // step inside the outermost object
    int depth = 1;  // 1 == directly inside the outermost object
    int[] end = new int[1];
    while (i < n && depth >= 1) {
      char c = body.charAt(i);
      if (c == '"') {
        String token = readString(body, i, end);
        int j = end[0];
        if (depth == 1) {
          int k = skipWs(body, j);
          if (k < n && body.charAt(k) == ':' && token.equals(key)) {
            // `token` is a matching top-level key
            return readValue(body, skipWs(body, k + 1), wantString, end);
          }
        }
        i = j;
        continue;
      }
      if (c == '{' || c == '[') {
        depth++;
      } else if (c == '}' || c == ']') {
        depth--;
      }
      i++;
    }
    return Optional.empty();
  }

  private static Optional<String> readValue(String body, int at, boolean wantString, int[] end) {
    int n = body.length();
    if (at >= n) {
      return Optional.empty();
    }
    char v = body.charAt(at);
    if (v == '"') {
      return wantString ? Optional.of(readString(body, at, end)) : Optional.empty();
    }
    if (wantString) {
      return Optional.empty();
    }
    int start = at;
    int k = at;
    while (k < n) {
      char c = body.charAt(k);
      if ((c >= '0' && c <= '9') || c == '-' || c == '+') {
        k++;
      } else {
        break;
      }
    }
    return k > start ? Optional.of(body.substring(start, k)) : Optional.empty();
  }

  /**
   * Reads a JSON string starting at {@code openQuote}. Returns the inner content
   * (escape sequences kept raw) and writes the index just past the closing quote
   * into {@code endOut[0]}.
   */
  private static String readString(String body, int openQuote, int[] endOut) {
    int n = body.length();
    StringBuilder sb = new StringBuilder();
    int i = openQuote + 1;
    while (i < n) {
      char c = body.charAt(i);
      if (c == '\\' && i + 1 < n) {
        sb.append(c).append(body.charAt(i + 1));
        i += 2;
        continue;
      }
      if (c == '"') {
        endOut[0] = i + 1;
        return sb.toString();
      }
      sb.append(c);
      i++;
    }
    endOut[0] = n; // unterminated string
    return sb.toString();
  }

  private static int skipWs(String body, int from) {
    int n = body.length();
    int i = from;
    while (i < n) {
      char c = body.charAt(i);
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        i++;
      } else {
        break;
      }
    }
    return i;
  }
}
