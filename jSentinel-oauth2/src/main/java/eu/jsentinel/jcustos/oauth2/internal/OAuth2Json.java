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
package eu.jsentinel.jcustos.oauth2.internal;

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

  /**
   * JS-SEC-043 (CWE-20): reads a top-level claim that RFC 7662 / RFC 7519 permit as EITHER a JSON
   * string OR an array of strings (notably {@code aud}). A scalar string yields a single-element
   * set; an array yields all of its string elements (non-string elements skipped); an absent or
   * otherwise-shaped value yields an empty set. Mirrors the String-or-array tolerance the JWT
   * {@code aud} path already has, so the opaque-token introspection path no longer silently drops
   * an array-form audience.
   *
   * @param body the JSON body
   * @param key  the top-level key
   * @return the audience values, never {@code null}
   */
  public static Set<String> stringOrArray(String body, String key) {
    Optional<String> scalar = string(body, key);
    if (scalar.isPresent()) {
      return Set.of(scalar.get());
    }
    return arrayStrings(body, key);
  }

  private static Set<String> arrayStrings(String body, String key) {
    if (body == null) {
      return Set.of();
    }
    int n = body.length();
    int i = body.indexOf('{');
    if (i < 0) {
      return Set.of();
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
            int v = skipWs(body, k + 1);
            return (v < n && body.charAt(v) == '[') ? readStringArray(body, v + 1) : Set.of();
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
    return Set.of();
  }

  private static Set<String> readStringArray(String body, int at) {
    int n = body.length();
    Set<String> out = new LinkedHashSet<>();
    int[] end = new int[1];
    int i = at;
    while (i < n) {
      char c = body.charAt(i);
      if (c == ']') {
        break;
      }
      if (c == '"') {
        out.add(readString(body, i, end));
        i = end[0];
        continue;
      }
      i++;
    }
    return Set.copyOf(out);
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
