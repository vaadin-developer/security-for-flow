package com.svenruppert.jsentinel.events.codec;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal in-tree canonical JSON engine (Konzept §454-§466). No Jackson, Gson
 * or org.json — those are Maven-Enforcer-banned on this module.
 *
 * <p>Canonical rules: UTF-8, no insignificant whitespace, object keys sorted
 * lexicographically, strings escaped deterministically, integers without a
 * fractional part. The engine handles exactly the value shapes the canonical
 * payload needs: objects, strings and non-negative integers.
 *
 * @since 00.75.00
 */
final class CanonicalJson {

  private CanonicalJson() {
  }

  /**
   * Writes a value in canonical form. Supported types: {@link Map} (rendered
   * as an object with sorted keys), {@link String}, {@link Integer} /
   * {@link Long}.
   */
  static void write(StringBuilder out, Object value) {
    switch (value) {
      case null -> throw new PayloadCodecException("canonical JSON does not encode null");
      case Map<?, ?> map -> writeObject(out, map);
      case String s -> writeString(out, s);
      case Integer i -> out.append(i.intValue());
      case Long l -> out.append(l.longValue());
      default -> throw new PayloadCodecException(
          "unsupported canonical JSON value type: " + value.getClass().getName());
    }
  }

  private static void writeObject(StringBuilder out, Map<?, ?> map) {
    TreeMap<String, Object> sorted = new TreeMap<>();
    for (Map.Entry<?, ?> e : map.entrySet()) {
      sorted.put(String.valueOf(e.getKey()), e.getValue());
    }
    out.append('{');
    boolean first = true;
    for (Map.Entry<String, Object> e : sorted.entrySet()) {
      if (!first) {
        out.append(',');
      }
      first = false;
      writeString(out, e.getKey());
      out.append(':');
      write(out, e.getValue());
    }
    out.append('}');
  }

  private static void writeString(StringBuilder out, String s) {
    out.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
  }

  /**
   * Parses a canonical JSON document into {@link Map} / {@link String} /
   * {@link Long} values.
   */
  static Object parse(String json) {
    Parser parser = new Parser(json);
    parser.skipWhitespace();
    Object value = parser.parseValue();
    parser.skipWhitespace();
    if (!parser.atEnd()) {
      throw new PayloadCodecException("trailing content in canonical JSON at index " + parser.pos);
    }
    return value;
  }

  private static final class Parser {
    private final String s;
    private int pos;

    Parser(String s) {
      this.s = s;
    }

    boolean atEnd() {
      return pos >= s.length();
    }

    void skipWhitespace() {
      while (pos < s.length()) {
        char c = s.charAt(pos);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
          pos++;
        } else {
          break;
        }
      }
    }

    Object parseValue() {
      if (atEnd()) {
        throw new PayloadCodecException("unexpected end of canonical JSON");
      }
      char c = s.charAt(pos);
      return switch (c) {
        case '{' -> parseObject();
        case '"' -> parseString();
        default -> parseNumber();
      };
    }

    Map<String, Object> parseObject() {
      expect('{');
      Map<String, Object> map = new LinkedHashMap<>();
      skipWhitespace();
      if (peek() == '}') {
        pos++;
        return map;
      }
      while (true) {
        skipWhitespace();
        String key = parseString();
        skipWhitespace();
        expect(':');
        skipWhitespace();
        map.put(key, parseValue());
        skipWhitespace();
        char c = next();
        if (c == ',') {
          continue;
        }
        if (c == '}') {
          return map;
        }
        throw new PayloadCodecException("expected ',' or '}' at index " + (pos - 1));
      }
    }

    String parseString() {
      expect('"');
      StringBuilder sb = new StringBuilder();
      while (true) {
        if (atEnd()) {
          throw new PayloadCodecException("unterminated string in canonical JSON");
        }
        char c = s.charAt(pos++);
        if (c == '"') {
          return sb.toString();
        }
        if (c == '\\') {
          char esc = s.charAt(pos++);
          switch (esc) {
            case '"' -> sb.append('"');
            case '\\' -> sb.append('\\');
            case '/' -> sb.append('/');
            case 'b' -> sb.append('\b');
            case 'f' -> sb.append('\f');
            case 'n' -> sb.append('\n');
            case 'r' -> sb.append('\r');
            case 't' -> sb.append('\t');
            case 'u' -> {
              String hex = s.substring(pos, pos + 4);
              pos += 4;
              sb.append((char) Integer.parseInt(hex, 16));
            }
            default -> throw new PayloadCodecException("invalid escape \\" + esc);
          }
        } else {
          sb.append(c);
        }
      }
    }

    Long parseNumber() {
      int start = pos;
      if (peek() == '-') {
        pos++;
      }
      while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
        pos++;
      }
      if (pos == start) {
        throw new PayloadCodecException("expected value at index " + start);
      }
      try {
        return Long.parseLong(s.substring(start, pos));
      } catch (NumberFormatException e) {
        throw new PayloadCodecException("invalid number at index " + start, e);
      }
    }

    char peek() {
      if (atEnd()) {
        throw new PayloadCodecException("unexpected end of canonical JSON");
      }
      return s.charAt(pos);
    }

    char next() {
      return s.charAt(pos++);
    }

    void expect(char c) {
      if (atEnd() || s.charAt(pos) != c) {
        throw new PayloadCodecException("expected '" + c + "' at index " + pos);
      }
      pos++;
    }
  }
}
