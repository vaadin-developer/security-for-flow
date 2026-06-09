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

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RestHeaders + BearerTokenExtractor")
class RestHeadersAndBearerTest {

  private final BearerTokenExtractor extractor = new BearerTokenExtractor();

  private RestRequest req(Map<String, String> headers) {
    return new RestRequest() {
      @Override public String method() { return "GET"; }
      @Override public String path() { return "/x"; }
      @Override public Map<String, String> headers() { return headers; }
      @Override public Map<String, String> queryParameters() { return Map.of(); }
    };
  }

  @Test
  @DisplayName("RestHeaders.first is case-insensitive")
  void caseInsensitive() {
    Optional<String> upper = RestHeaders.first(req(Map.of("Authorization", "Bearer x")), "authorization");
    Optional<String> lower = RestHeaders.first(req(Map.of("authorization", "Bearer y")), "Authorization");
    assertEquals("Bearer x", upper.orElseThrow());
    assertEquals("Bearer y", lower.orElseThrow());
  }

  @Test
  @DisplayName("BearerTokenExtractor extracts a valid Bearer token")
  void valid() {
    assertEquals("abc-123", extractor.extract(req(Map.of("Authorization", "Bearer abc-123"))).orElseThrow());
  }

  @Test
  @DisplayName("BearerTokenExtractor: scheme is matched case-insensitively, token whitespace is trimmed")
  void caseAndTrim() {
    assertEquals("abc",
        extractor.extract(req(Map.of("Authorization", "bearer   abc   "))).orElseThrow());
  }

  @Test
  @DisplayName("missing Authorization header returns empty")
  void missing() {
    assertTrue(extractor.extract(req(Map.of())).isEmpty());
  }

  @Test
  @DisplayName("non-Bearer scheme returns empty")
  void wrongScheme() {
    assertTrue(extractor.extract(req(Map.of("Authorization", "Basic dXNlcjpwYXNz"))).isEmpty());
  }

  @Test
  @DisplayName("Bearer with empty token returns empty")
  void emptyToken() {
    assertTrue(extractor.extract(req(Map.of("Authorization", "Bearer    "))).isEmpty());
  }

  @Test
  @DisplayName("RestHeaders.first returns empty when the directly-keyed value is blank")
  void blankDirectMatchReturnsEmpty() {
    Optional<String> result = RestHeaders.first(
        req(Map.of("Authorization", "   ")), "Authorization");

    assertTrue(result.isEmpty(),
        "a blank value on a direct key match must NOT be returned");
  }

  @Test
  @DisplayName("RestHeaders.first scans case-insensitively when no direct match exists")
  void caseInsensitiveFallthroughFindsHeader() {
    Optional<String> result = RestHeaders.first(
        req(Map.of("AUTHORIZATION", "Bearer x")), "Authorization");

    assertEquals("Bearer x", result.orElseThrow());
  }

  @Test
  @DisplayName("RestHeaders.first ignores blank values during the case-insensitive scan")
  void caseInsensitiveScanIgnoresBlank() {
    Optional<String> result = RestHeaders.first(
        req(Map.of("AUTHORIZATION", "   ")), "Authorization");

    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("RestHeaders.first returns empty for null request or null name")
  void nullArguments() {
    assertTrue(RestHeaders.first(null, "Authorization").isEmpty());
    assertTrue(RestHeaders.first(req(Map.of("Authorization", "Bearer x")), null).isEmpty());
  }

  @Test
  @DisplayName("RestHeaders.first returns empty when no header matches at all")
  void noMatch() {
    assertTrue(RestHeaders.first(
        req(Map.of("Content-Type", "application/json")), "Authorization").isEmpty());
  }
}
