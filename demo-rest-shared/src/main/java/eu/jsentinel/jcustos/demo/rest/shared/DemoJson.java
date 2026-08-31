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
package eu.jsentinel.jcustos.demo.rest.shared;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Tiny demo JSON encoder/decoder using only JDK APIs. Demo-only — not a
 * production JSON implementation.
 */
public final class DemoJson {

  private DemoJson() {
  }

  public static String encode(Object value) {
    StringBuilder sb = new StringBuilder();
    write(sb, value);
    return sb.toString();
  }

  public static Map<String, Object> decodeObject(String json) {
    Parser parser = new Parser(json);
    Object value = parser.readValue();
    if (!(value instanceof Map<?, ?> raw)) {
      throw new IllegalArgumentException("Expected JSON object");
    }
    @SuppressWarnings("unchecked")
    Map<String, Object> result = (Map<String, Object>) raw;
    return result;
  }

  private static void write(StringBuilder sb, Object v) {
    switch (v) {
      case null -> sb.append("null");
      case String s -> writeString(sb, s);
      case Boolean b -> sb.append(b);
      case Number n -> sb.append(n);
      case Map<?, ?> m -> {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : m.entrySet()) {
          if (!first) sb.append(',');
          writeString(sb, String.valueOf(e.getKey()));
          sb.append(':');
          write(sb, e.getValue());
          first = false;
        }
        sb.append('}');
      }
      case Iterable<?> it -> {
        sb.append('[');
        boolean first = true;
        for (Object x : it) {
          if (!first) sb.append(',');
          write(sb, x);
          first = false;
        }
        sb.append(']');
      }
      default -> writeString(sb, v.toString());
    }
  }

  private static void writeString(StringBuilder sb, String s) {
    sb.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> sb.append("\\\"");
        case '\\' -> sb.append("\\\\");
        case '\n' -> sb.append("\\n");
        case '\r' -> sb.append("\\r");
        case '\t' -> sb.append("\\t");
        default -> {
          if (c < 0x20) {
            sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
        }
      }
    }
    sb.append('"');
  }

  private static final class Parser {
    private final String s;
    private int i;

    Parser(String s) {
      this.s = s;
    }

    Object readValue() {
      skipWs();
      if (i >= s.length()) throw new IllegalArgumentException("Unexpected end of JSON");
      char c = s.charAt(i);
      return switch (c) {
        case '{' -> readObject();
        case '[' -> readArray();
        case '"' -> readString();
        case 't', 'f' -> readBool();
        case 'n' -> readNull();
        default -> readNumber();
      };
    }

    private Map<String, Object> readObject() {
      expect('{');
      Map<String, Object> map = new LinkedHashMap<>();
      skipWs();
      if (peek() == '}') {
        i++;
        return map;
      }
      while (true) {
        skipWs();
        String key = readString();
        skipWs();
        expect(':');
        Object value = readValue();
        map.put(key, value);
        skipWs();
        char c = peek();
        if (c == ',') {
          i++;
          continue;
        }
        if (c == '}') {
          i++;
          return map;
        }
        throw new IllegalArgumentException("Expected , or } in object");
      }
    }

    private List<Object> readArray() {
      expect('[');
      List<Object> list = new ArrayList<>();
      skipWs();
      if (peek() == ']') {
        i++;
        return list;
      }
      while (true) {
        list.add(readValue());
        skipWs();
        char c = peek();
        if (c == ',') {
          i++;
          continue;
        }
        if (c == ']') {
          i++;
          return list;
        }
        throw new IllegalArgumentException("Expected , or ] in array");
      }
    }

    private String readString() {
      expect('"');
      StringBuilder sb = new StringBuilder();
      while (i < s.length()) {
        char c = s.charAt(i++);
        if (c == '"') return sb.toString();
        if (c == '\\') {
          char e = s.charAt(i++);
          switch (e) {
            case '"' -> sb.append('"');
            case '\\' -> sb.append('\\');
            case '/' -> sb.append('/');
            case 'n' -> sb.append('\n');
            case 'r' -> sb.append('\r');
            case 't' -> sb.append('\t');
            case 'b' -> sb.append('\b');
            case 'f' -> sb.append('\f');
            case 'u' -> {
              String hex = s.substring(i, i + 4);
              sb.append((char) Integer.parseInt(hex, 16));
              i += 4;
            }
            default -> throw new IllegalArgumentException("Bad escape: \\" + e);
          }
        } else {
          sb.append(c);
        }
      }
      throw new IllegalArgumentException("Unterminated string");
    }

    private Boolean readBool() {
      if (s.startsWith("true", i)) {
        i += 4;
        return Boolean.TRUE;
      }
      if (s.startsWith("false", i)) {
        i += 5;
        return Boolean.FALSE;
      }
      throw new IllegalArgumentException("Expected boolean");
    }

    private Object readNull() {
      if (s.startsWith("null", i)) {
        i += 4;
        return null;
      }
      throw new IllegalArgumentException("Expected null");
    }

    private Number readNumber() {
      int start = i;
      if (peek() == '-') i++;
      while (i < s.length()) {
        char c = s.charAt(i);
        if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
          i++;
        } else {
          break;
        }
      }
      String n = s.substring(start, i);
      if (n.contains(".") || n.contains("e") || n.contains("E")) {
        return Double.parseDouble(n);
      }
      return Long.parseLong(n);
    }

    private char peek() {
      return i < s.length() ? s.charAt(i) : '\0';
    }

    private void skipWs() {
      while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    private void expect(char c) {
      skipWs();
      if (i >= s.length() || s.charAt(i) != c) {
        throw new IllegalArgumentException("Expected '" + c + "'");
      }
      i++;
    }
  }
}
