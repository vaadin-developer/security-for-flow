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
package eu.jsentinel.jcustos.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileBootstrapTokenOutputTest {

  private static final BootstrapToken TOKEN = new BootstrapToken(
      "SECRET-TOKEN-VALUE", Instant.parse("2026-01-01T00:00:00Z"));

  private static String render(BootstrapConfiguration cfg) {
    ByteArrayOutputStream sink = new ByteArrayOutputStream();
    FileBootstrapTokenOutput out = new FileBootstrapTokenOutput(
        new PrintStream(sink, true, StandardCharsets.UTF_8));
    out.emit(TOKEN, cfg);
    return sink.toString(StandardCharsets.UTF_8);
  }

  @Test
  @DisplayName("banner mentions the file path but never the token value")
  void bannerLogsPathNotTokenValue() {
    Path tokenFile = Path.of("./data/bootstrap.token");
    String text = render(BootstrapConfiguration.persistent(tokenFile));

    assertTrue(text.contains("Initial administrator setup required."));
    assertTrue(text.contains("Bootstrap token file:"));
    assertTrue(text.contains(tokenFile.toAbsolutePath().toString()),
        "absolute file path must appear");
    assertTrue(text.contains(
        "Use the value in the file to complete the initial admin setup."));
    assertFalse(text.contains("SECRET-TOKEN-VALUE"),
        "token value must NEVER be logged in file mode");
  }

  @Test
  @DisplayName("a missing path falls back to '(unknown)'")
  void unknownPathPlaceholder() {
    BootstrapConfiguration cfg = new BootstrapConfiguration(
        BootstrapMode.TRANSIENT_CONSOLE, null, BootstrapConfiguration.DEFAULT_VALIDITY);
    String text = render(cfg);

    assertTrue(text.contains("(unknown)"),
        "null tokenFilePath should be replaced by '(unknown)'");
  }

  @Test
  @DisplayName("emit produces exactly 9 newlines (one per println call)")
  void exactNewlineCount() {
    String text = render(BootstrapConfiguration.persistent(
        Path.of("./data/bootstrap.token")));

    long newlines = text.chars().filter(c -> c == '\n').count();
    assertEquals(9, newlines, "9 println() calls expected");
  }

  @Test
  @DisplayName("the banner contains both horizontal rule lines")
  void hasTwoHorizontalRules() {
    String text = render(BootstrapConfiguration.persistent(
        Path.of("./data/bootstrap.token")));

    String rule = "============================================================";
    int first = text.indexOf(rule);
    assertTrue(first >= 0, "first horizontal rule missing");
    int second = text.indexOf(rule, first + rule.length());
    assertTrue(second > first, "second horizontal rule missing");
  }

  @Test
  @DisplayName("output starts and ends with a blank line for readability")
  void framedByBlankLines() {
    String text = render(BootstrapConfiguration.persistent(
        Path.of("./data/bootstrap.token")));

    assertEquals('\n', text.charAt(0));
    assertTrue(text.endsWith("\n\n"));
  }
}
