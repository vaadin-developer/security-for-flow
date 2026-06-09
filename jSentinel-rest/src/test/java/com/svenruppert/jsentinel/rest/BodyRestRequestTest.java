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
package com.svenruppert.jsentinel.rest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BodyRestRequestTest {

  private static BodyRestRequest withBody(byte[] body) {
    return new BodyRestRequest() {
      @Override public String method() { return "POST"; }
      @Override public String path() { return "/x"; }
      @Override public Map<String, String> headers() { return Map.of(); }
      @Override public Map<String, String> queryParameters() { return Map.of(); }
      @Override public byte[] bodyBytes() { return body; }
    };
  }

  @Test
  @DisplayName("bodyAsUtf8 decodes raw bytes as UTF-8")
  void bodyAsUtf8() {
    byte[] payload = "über".getBytes(StandardCharsets.UTF_8);
    assertEquals("über", withBody(payload).bodyAsUtf8());
  }

  @Test
  @DisplayName("bodyAsString uses the supplied charset")
  void bodyAsStringHonoursCharset() {
    byte[] payload = "über".getBytes(StandardCharsets.UTF_8);
    BodyRestRequest req = withBody(payload);

    String utf8 = req.bodyAsString(StandardCharsets.UTF_8);
    String iso = req.bodyAsString(StandardCharsets.ISO_8859_1);

    assertEquals("über", utf8);
    // bytes 0xC3 0xBC interpreted as ISO-8859-1 produce two distinct chars
    assertEquals(2, "über".getBytes(StandardCharsets.UTF_8).length - "ber".length());
    assertEquals("Ã¼ber", iso,
        "ISO-8859-1 decoding of UTF-8 bytes must differ from UTF-8 decoding");
  }

  @Test
  @DisplayName("bodyAsUtf8 returns empty string when bytes are empty")
  void bodyAsUtf8Empty() {
    assertEquals("", withBody(new byte[0]).bodyAsUtf8());
  }

  @Test
  @DisplayName("bodyAsString with ASCII bytes round-trips identically across charsets")
  void asciiRoundTrip() {
    byte[] ascii = "hello".getBytes(StandardCharsets.US_ASCII);
    BodyRestRequest req = withBody(ascii);

    assertEquals("hello", req.bodyAsString(StandardCharsets.US_ASCII));
    assertEquals("hello", req.bodyAsString(StandardCharsets.UTF_8));
    assertEquals("hello", req.bodyAsUtf8());
  }
}
