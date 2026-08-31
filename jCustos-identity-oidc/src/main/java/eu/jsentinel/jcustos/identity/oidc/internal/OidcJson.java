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
package eu.jsentinel.jcustos.identity.oidc.internal;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, strict, dependency-free JSON parser (V00.78) for OIDC discovery +
 * UserInfo responses — the {@code jCustos-identity-oidc} module bans Jackson /
 * Gson / org.json, so it parses in-tree. Produces {@link Map} / {@link List} /
 * {@link String} / {@link Long} / {@link Double} / {@link Boolean} / {@code null}.
 * Nesting is depth-capped (defence against stack-exhausting input); the HTTP layer
 * caps the byte size. Trailing non-whitespace after the top-level value is rejected.
 */
public final class OidcJson {

  private static final int MAX_DEPTH = 64;

  /** Thrown on malformed JSON. */
  public static final class JsonException extends RuntimeException {
    public JsonException(String message) {
      super(message);
    }
  }

  private final String s;
  private int i;

  private OidcJson(String s) {
    this.s = s;
  }

  /**
   * Parses a complete JSON document.
   *
   * @param json the JSON text
   * @return the parsed value (Map / List / String / Long / Double / Boolean / null)
   * @throws JsonException if the text is not a single well-formed JSON value
   */
  public static Object parse(String json) {
    OidcJson p = new OidcJson(json);
    p.skipWs();
    Object value = p.value(0);
    p.skipWs();
    if (p.i != p.s.length()) {
      throw new JsonException("trailing content after JSON value at " + p.i);
    }
    return value;
  }

  /** Parses a JSON object, or throws if the top-level value is not an object. */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> parseObject(String json) {
    Object value = parse(json);
    if (!(value instanceof Map)) {
      throw new JsonException("expected a JSON object");
    }
    return (Map<String, Object>) value;
  }

  private Object value(int depth) {
    if (depth > MAX_DEPTH) {
      throw new JsonException("max nesting depth exceeded");
    }
    if (i >= s.length()) {
      throw new JsonException("unexpected end of input");
    }
    char c = s.charAt(i);
    return switch (c) {
      case '{' -> object(depth);
      case '[' -> array(depth);
      case '"' -> string();
      case 't', 'f' -> bool();
      case 'n' -> nul();
      default -> number();
    };
  }

  private Map<String, Object> object(int depth) {
    expect('{');
    Map<String, Object> map = new LinkedHashMap<>();
    skipWs();
    if (peek() == '}') {
      i++;
      return map;
    }
    while (true) {
      skipWs();
      if (peek() != '"') {
        throw new JsonException("expected string key at " + i);
      }
      String key = string();
      skipWs();
      expect(':');
      skipWs();
      map.put(key, value(depth + 1));
      skipWs();
      char c = next();
      if (c == '}') {
        return map;
      }
      if (c != ',') {
        throw new JsonException("expected ',' or '}' at " + (i - 1));
      }
    }
  }

  private List<Object> array(int depth) {
    expect('[');
    List<Object> list = new ArrayList<>();
    skipWs();
    if (peek() == ']') {
      i++;
      return list;
    }
    while (true) {
      skipWs();
      list.add(value(depth + 1));
      skipWs();
      char c = next();
      if (c == ']') {
        return list;
      }
      if (c != ',') {
        throw new JsonException("expected ',' or ']' at " + (i - 1));
      }
    }
  }

  private String string() {
    expect('"');
    StringBuilder sb = new StringBuilder();
    while (true) {
      if (i >= s.length()) {
        throw new JsonException("unterminated string");
      }
      char c = s.charAt(i++);
      if (c == '"') {
        return sb.toString();
      }
      if (c == '\\') {
        char e = next();
        switch (e) {
          case '"' -> sb.append('"');
          case '\\' -> sb.append('\\');
          case '/' -> sb.append('/');
          case 'b' -> sb.append('\b');
          case 'f' -> sb.append('\f');
          case 'n' -> sb.append('\n');
          case 'r' -> sb.append('\r');
          case 't' -> sb.append('\t');
          case 'u' -> {
            if (i + 4 > s.length()) {
              throw new JsonException("truncated unicode escape");
            }
            // R-EXIT: reject non-hex escapes here — Integer.parseInt would otherwise
            // throw an uncaught NumberFormatException, escaping the Result channel.
            int code = 0;
            for (int h = 0; h < 4; h++) {
              int digit = Character.digit(s.charAt(i + h), 16);
              if (digit < 0) {
                throw new JsonException("invalid unicode escape");
              }
              code = (code << 4) | digit;
            }
            sb.append((char) code);
            i += 4;
          }
          default -> throw new JsonException("invalid escape \\" + e);
        }
      } else if (c < 0x20) {
        throw new JsonException("unescaped control character in string");
      } else {
        sb.append(c);
      }
    }
  }

  private Object number() {
    int start = i;
    if (peek() == '-') {
      i++;
    }
    boolean integral = true;
    while (i < s.length()) {
      char c = s.charAt(i);
      if (c >= '0' && c <= '9') {
        i++;
      } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
        integral = false;
        i++;
      } else {
        break;
      }
    }
    String num = s.substring(start, i);
    if (num.isEmpty() || "-".equals(num)) {
      throw new JsonException("invalid number at " + start);
    }
    try {
      return integral ? (Object) Long.parseLong(num) : (Object) Double.parseDouble(num);
    } catch (NumberFormatException e) {
      throw new JsonException("invalid number: " + num);
    }
  }

  private Boolean bool() {
    if (s.startsWith("true", i)) {
      i += 4;
      return Boolean.TRUE;
    }
    if (s.startsWith("false", i)) {
      i += 5;
      return Boolean.FALSE;
    }
    throw new JsonException("invalid literal at " + i);
  }

  private Object nul() {
    if (s.startsWith("null", i)) {
      i += 4;
      return null;
    }
    throw new JsonException("invalid literal at " + i);
  }

  private void expect(char c) {
    if (next() != c) {
      throw new JsonException("expected '" + c + "' at " + (i - 1));
    }
  }

  private char next() {
    if (i >= s.length()) {
      throw new JsonException("unexpected end of input");
    }
    return s.charAt(i++);
  }

  private char peek() {
    return i < s.length() ? s.charAt(i) : '\0';
  }

  private void skipWs() {
    while (i < s.length()) {
      char c = s.charAt(i);
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        i++;
      } else {
        break;
      }
    }
  }
}
