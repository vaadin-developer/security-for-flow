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
package com.svenruppert.vaadin.security.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsoleBootstrapTokenOutputTest {

  private static final BootstrapToken TOKEN = new BootstrapToken(
      "AAAA-BBBB-CCCC-DDDD-EEEE", Instant.parse("2026-01-01T00:00:00Z"));
  private static final BootstrapConfiguration CFG = BootstrapConfiguration.transientConsole();

  private static String render(ConsoleBootstrapTokenOutput out, ByteArrayOutputStream sink) {
    out.emit(TOKEN, CFG);
    return sink.toString(StandardCharsets.UTF_8);
  }

  @Test
  @DisplayName("banner contains all fixed lines and the token value")
  void bannerContent() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), "Open /setup");

    String text = render(out, sink);

    assertTrue(text.contains("Initial administrator setup required."),
        "missing setup-required line");
    assertTrue(text.contains("Open /setup"), "missing setup hint");
    assertTrue(text.contains("Bootstrap token:"), "missing token label");
    assertTrue(text.contains("AAAA-BBBB-CCCC-DDDD-EEEE"), "missing token value");
    assertTrue(text.contains(
        "This token is single-use and only valid while the system is uninitialized."),
        "missing single-use disclaimer");
    assertTrue(text.contains("============================================================"),
        "missing horizontal rule");
  }

  @Test
  @DisplayName("token value sits indented on its own line")
  void tokenIsIndented() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), "");

    String text = render(out, sink);

    assertTrue(text.contains("  AAAA-BBBB-CCCC-DDDD-EEEE"),
        "token line should be 2-space indented");
  }

  @Test
  @DisplayName("setup hint section is omitted when blank")
  void emptyHintIsOmitted() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), "");

    String text = render(out, sink);

    assertFalse(text.contains("Open /setup"),
        "no hint provided — should not appear");
  }

  @Test
  @DisplayName("null setup hint is treated as empty")
  void nullHintTreatedAsEmpty() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), null);

    String text = render(out, sink);

    assertTrue(text.contains("AAAA-BBBB-CCCC-DDDD-EEEE"));
    assertTrue(text.contains("Bootstrap token:"));
  }

  @Test
  @DisplayName("emit produces exactly the expected number of newlines (12 \\n total)")
  void exactNewlineCount() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), "Open /setup");

    String text = render(out, sink);

    long newlines = text.chars().filter(c -> c == '\n').count();
    assertEquals(12, newlines,
        "12 println() calls expected (incl. setup-hint section). Got: " + newlines);
  }

  @Test
  @DisplayName("emit produces 10 newlines without the setup hint")
  void newlineCountWithoutHint() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), "");

    String text = render(out, sink);

    long newlines = text.chars().filter(c -> c == '\n').count();
    assertEquals(10, newlines, "10 println() calls expected without hint");
  }

  @Test
  @DisplayName("first emitted character is a blank-line separator (println before banner)")
  void leadsWithBlankLine() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), "");

    String text = render(out, sink);

    assertEquals('\n', text.charAt(0),
        "banner should start with a leading blank line for readability");
  }

  @Test
  @DisplayName("output ends with a trailing blank line")
  void endsWithBlankLine() {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    ConsoleBootstrapTokenOutput out = new ConsoleBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8), "");

    String text = render(out, sink);

    assertTrue(text.endsWith("\n\n"),
        "banner should end with a trailing blank line");
  }
}
