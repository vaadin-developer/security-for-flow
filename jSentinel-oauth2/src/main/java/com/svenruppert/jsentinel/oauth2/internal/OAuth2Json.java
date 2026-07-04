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
package com.svenruppert.jsentinel.oauth2.internal;

/*-
 * #%L
 * jSentinel OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Minimal, depth-aware JSON field extractor for OAuth2 token / introspection /
 * device responses (V00.77) — no third-party JSON library. Mirrors the
 * R09-hardened {@code jSentinel-propagation-oidc} scanner: it only matches keys
 * that are direct members of the outermost object, tracking nesting depth and
 * string literals (honouring {@code \\} escapes), so a nested or
 * value-embedded key can never be grabbed. The V00.77.x consolidation (B6)
 * unifies this with the propagation-oidc copy.
 */
public final class OAuth2Json {

  private OAuth2Json() {
    throw new AssertionError("no instances");
  }

  /** @return the top-level string field {@code key}, or empty. */
  public static Optional<String> string(String body, String key) {
    return topLevelValue(body, key, true);
  }

  /** @return the top-level numeric field {@code key} as a long, or empty (overflow-safe). */
  public static Optional<Long> longValue(String body, String key) {
    return topLevelValue(body, key, false).flatMap(token -> {
      try {
        return Optional.of(Long.parseLong(token));
      } catch (NumberFormatException overflow) {
        return Optional.empty();
      }
    });
  }

  /** @return the top-level boolean field {@code key}, or empty. */
  public static Optional<Boolean> bool(String body, String key) {
    return topLevelValue(body, key, false).flatMap(token -> switch (token) {
      case "true" -> Optional.of(Boolean.TRUE);
      case "false" -> Optional.of(Boolean.FALSE);
      default -> Optional.empty();
    });
  }

  /**
   * JS-SEC-034 (CWE-248): parse an RFC 6749 scope string into a set without
   * {@code Set.of}'s duplicate-hostility. Splits on whitespace, drops blanks and
   * de-duplicates into an insertion-ordered {@link LinkedHashSet}. {@code Set.of}
   * throws {@link IllegalArgumentException} on a duplicate scope (or an empty token
   * from consecutive spaces), which escaped the module's {@code Result} never-throw
   * contract on a non-conformant authorization-server response.
   *
   * @param scope the raw {@code scope} value (may be {@code null} / blank)
   * @return the de-duplicated scopes, never {@code null}
   */
  public static Set<String> parseScopes(String scope) {
    if (scope == null || scope.isBlank()) {
      return Set.of();
    }
    return Arrays.stream(scope.trim().split("\\s+"))
        .filter(token -> !token.isEmpty())
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  private static Optional<String> topLevelValue(String body, String key, boolean wantString) {
    if (body == null) {
      return Optional.empty();
    }
    int n = body.length();
    int i = body.indexOf('{');
    if (i < 0) {
      return Optional.empty();
    }
    i++;
    int depth = 1;
    int[] end = new int[1];
    while (i < n && depth >= 1) {
      char c = body.charAt(i);
      if (c == '"') {
        String token = readString(body, i, end);
        int j = end[0];
        if (depth == 1) {
          int k = skipWs(body, j);
          if (k < n && body.charAt(k) == ':' && token.equals(key)) {
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
    // bare literal: digits, sign, or true/false
    int start = at;
    int k = at;
    while (k < n) {
      char c = body.charAt(k);
      if ((c >= '0' && c <= '9') || c == '-' || (c >= 'a' && c <= 'z')) {
        k++;
      } else {
        break;
      }
    }
    return k > start ? Optional.of(body.substring(start, k)) : Optional.empty();
  }

  private static String readString(String body, int openQuote, int[] endOut) {
    int n = body.length();
    StringBuilder sb = new StringBuilder();
    int i = openQuote + 1;
    while (i < n) {
      char c = body.charAt(i);
      if (c == '\\' && i + 1 < n) {
        char next = body.charAt(i + 1);
        // decode the common JSON escapes; keep others raw
        switch (next) {
          case '"' -> sb.append('"');
          case '\\' -> sb.append('\\');
          case '/' -> sb.append('/');
          case 'n' -> sb.append('\n');
          case 't' -> sb.append('\t');
          case 'r' -> sb.append('\r');
          default -> sb.append(c).append(next);
        }
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
    endOut[0] = n;
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
