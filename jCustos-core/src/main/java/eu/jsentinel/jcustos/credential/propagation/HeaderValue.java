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
package eu.jsentinel.jcustos.credential.propagation;


import java.util.Objects;

/**
 * Result of an {@link OutboundTokenStrategy} — a single HTTP header
 * the consumer's HTTP client applies before sending.
 *
 * <p>The canonical constructor validates the header per
 * RFC 7230 §3.2.6. {@code name} must consist of {@code tchar}s
 * exclusively; both {@code name} and {@code value} reject CR / LF and
 * bare control characters (the RFC obs-text allowance for high bytes
 * is preserved on {@code value}).
 *
 * @param name  HTTP header name (e.g. {@code Authorization}); validated
 *              against the {@code tchar} grammar
 * @param value HTTP header value; CR / LF / control bytes rejected
 *
 * @since 00.74.00
 */
public record HeaderValue(String name, String value) {

  public HeaderValue {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(value, "value");
    if (name.isEmpty()) {
      throw new IllegalArgumentException("HeaderValue name must be non-empty");
    }
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      if (!isTchar(c)) {
        throw new IllegalArgumentException(
            "HeaderValue name contains an invalid RFC 7230 tchar at index " + i);
      }
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == '\r' || c == '\n') {
        throw new IllegalArgumentException(
            "HeaderValue value must not contain CR / LF at index " + i);
      }
      if (c < 0x20 && c != '\t') {
        throw new IllegalArgumentException(
            "HeaderValue value must not contain control bytes at index " + i);
      }
    }
  }

  /**
   * RFC 7230 §3.2.6 {@code tchar}:
   * {@code "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "."
   *  / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA}.
   */
  private static boolean isTchar(char c) {
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    return switch (c) {
      case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.',
           '^', '_', '`', '|', '~' -> true;
      default -> false;
    };
  }
}
