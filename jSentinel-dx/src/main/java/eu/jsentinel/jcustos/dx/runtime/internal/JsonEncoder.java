/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package eu.jsentinel.jcustos.dx.runtime.internal;

import java.util.Iterator;
import java.util.Map;

/**
 * Minimal RFC 8259 JSON encoder for {@link eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime#toJson()}.
 * <p>
 * Supported value types: {@code null}, {@link Boolean}, {@link Number},
 * {@link CharSequence}, {@link Map} and {@link Iterable}. Maps and
 * iterables are recursed; their entries / elements must in turn be
 * supported. Any other type throws {@link JsonEncodeException} — the
 * intent is to keep the encoder small and predictable, not to be a
 * general-purpose JSON library.
 * <p>
 * Output discipline:
 * <ul>
 *   <li>Strings are escaped per RFC 8259 §7: {@code "}, {@code &#92;},
 *       {@code &#92;n}, {@code &#92;r}, {@code &#92;t}, {@code &#92;b},
 *       {@code &#92;f}, and {@code &#92;u00XX} for control characters
 *       below U+0020.
 *   <li>Numbers go through {@link String#valueOf(Object)} — primitive
 *       wrappers and {@link java.math.BigDecimal} survive a round-trip;
 *       non-finite {@code double}s ({@code NaN} / {@code ±Infinity}) are
 *       rejected because RFC 8259 §6 forbids them.
 *   <li>Map keys are coerced to {@link String} via
 *       {@link Object#toString()} and escaped; a {@code null} key throws.
 *   <li>Maps preserve insertion order — pair with a {@link java.util.LinkedHashMap}
 *       on the producer side for deterministic JSON output.
 * </ul>
 *
 * <p>This class lives in the {@code eu.jsentinel.jcustos.dx.runtime.internal}
 * package — by convention, classes in {@code internal} packages are
 * <strong>not</strong> part of the public API surface. The public entry
 * point is {@link eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime#toJson()}.
 * The Maven Enforcer rule on {@code jSentinel-dx} blocks every third-party
 * JSON library on compile/runtime scope precisely so this stays the only
 * JSON code path on the DX classpath (compare V00.74.10 §3 invariant 1).
 *
 * @since 00.74.10
 */
public final class JsonEncoder {

  private JsonEncoder() { }

  public static String encode(Object value) {
    StringBuilder out = new StringBuilder(256);
    writeValue(value, out);
    return out.toString();
  }

  private static void writeValue(Object value, StringBuilder out) {
    switch (value) {
      case null -> out.append("null");
      case Boolean b -> out.append(b.booleanValue());
      case Number n -> writeNumber(n, out);
      case CharSequence cs -> writeString(cs, out);
      case Map<?, ?> m -> writeObject(m, out);
      case Iterable<?> it -> writeArray(it, out);
      default -> throw new JsonEncodeException(
          "Unsupported JSON value type: " + value.getClass().getName());
    }
  }

  private static void writeNumber(Number n, StringBuilder out) {
    if (n instanceof Double d) {
      if (d.isInfinite() || d.isNaN()) {
        throw new JsonEncodeException(
            "Non-finite double is not valid JSON (RFC 8259 §6): " + d);
      }
    } else if (n instanceof Float f) {
      if (f.isInfinite() || f.isNaN()) {
        throw new JsonEncodeException(
            "Non-finite float is not valid JSON (RFC 8259 §6): " + f);
      }
    }
    out.append(n);
  }

  private static void writeString(CharSequence value, StringBuilder out) {
    out.append('"');
    int len = value.length();
    for (int i = 0; i < len; i++) {
      char c = value.charAt(i);
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
            out.append("\\u");
            String hex = Integer.toHexString(c);
            for (int pad = 4 - hex.length(); pad > 0; pad--) out.append('0');
            out.append(hex);
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
  }

  private static void writeObject(Map<?, ?> map, StringBuilder out) {
    out.append('{');
    Iterator<? extends Map.Entry<?, ?>> it = map.entrySet().iterator();
    boolean first = true;
    while (it.hasNext()) {
      Map.Entry<?, ?> entry = it.next();
      Object key = entry.getKey();
      if (key == null) {
        throw new JsonEncodeException("JSON object key must not be null");
      }
      if (!first) out.append(',');
      writeString(key.toString(), out);
      out.append(':');
      writeValue(entry.getValue(), out);
      first = false;
    }
    out.append('}');
  }

  private static void writeArray(Iterable<?> values, StringBuilder out) {
    out.append('[');
    Iterator<?> it = values.iterator();
    boolean first = true;
    while (it.hasNext()) {
      if (!first) out.append(',');
      writeValue(it.next(), out);
      first = false;
    }
    out.append(']');
  }
}
