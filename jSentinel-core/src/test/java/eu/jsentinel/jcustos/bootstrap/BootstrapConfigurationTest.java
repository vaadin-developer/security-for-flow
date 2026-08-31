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

import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BootstrapConfigurationTest {

  @Test
  @DisplayName("disabled() encodes DISABLED + default validity + no path")
  void disabledPreset() {
    BootstrapConfiguration c = BootstrapConfiguration.disabled();
    assertNotNull(c);
    assertSame(BootstrapMode.DISABLED, c.mode());
    assertNull(c.tokenFilePath());
    assertEquals(BootstrapConfiguration.DEFAULT_VALIDITY, c.tokenValidity());
  }

  @Test
  @DisplayName("transientConsole() encodes TRANSIENT_CONSOLE + default validity + no path")
  void transientConsolePreset() {
    BootstrapConfiguration c = BootstrapConfiguration.transientConsole();
    assertNotNull(c);
    assertSame(BootstrapMode.TRANSIENT_CONSOLE, c.mode());
    assertNull(c.tokenFilePath());
    assertEquals(BootstrapConfiguration.DEFAULT_VALIDITY, c.tokenValidity());
  }

  @Test
  @DisplayName("transientConsole(duration) keeps the explicit validity")
  void transientConsoleWithCustomValidity() {
    Duration ttl = Duration.ofMinutes(15);
    BootstrapConfiguration c = BootstrapConfiguration.transientConsole(ttl);
    assertSame(BootstrapMode.TRANSIENT_CONSOLE, c.mode());
    assertEquals(ttl, c.tokenValidity());
  }

  @Test
  @DisplayName("persistent(path) defaults to DEFAULT_VALIDITY")
  void persistentDefaultValidity() {
    Path p = Path.of("./data/bootstrap.token");
    BootstrapConfiguration c = BootstrapConfiguration.persistent(p);
    assertSame(BootstrapMode.PERSISTENT_FILE, c.mode());
    assertEquals(p, c.tokenFilePath());
    assertEquals(BootstrapConfiguration.DEFAULT_VALIDITY, c.tokenValidity());
  }

  @Test
  @DisplayName("persistent(path, ttl) keeps both explicit values")
  void persistentExplicit() {
    Path p = Path.of("./data/bootstrap.token");
    Duration ttl = Duration.ofHours(2);
    BootstrapConfiguration c = BootstrapConfiguration.persistent(p, ttl);
    assertSame(BootstrapMode.PERSISTENT_FILE, c.mode());
    assertEquals(p, c.tokenFilePath());
    assertEquals(ttl, c.tokenValidity());
  }

  @Test
  @DisplayName("constructor rejects null mode")
  void rejectsNullMode() {
    assertThrows(NullPointerException.class,
        () -> new BootstrapConfiguration(null, null, BootstrapConfiguration.DEFAULT_VALIDITY));
  }

  @Test
  @DisplayName("constructor rejects null tokenValidity")
  void rejectsNullValidity() {
    assertThrows(NullPointerException.class,
        () -> new BootstrapConfiguration(BootstrapMode.DISABLED, null, null));
  }

  @Test
  @DisplayName("constructor rejects zero validity")
  void rejectsZeroValidity() {
    assertThrows(IllegalArgumentException.class,
        () -> new BootstrapConfiguration(BootstrapMode.DISABLED, null, Duration.ZERO));
  }

  @Test
  @DisplayName("constructor rejects negative validity")
  void rejectsNegativeValidity() {
    assertThrows(IllegalArgumentException.class,
        () -> new BootstrapConfiguration(BootstrapMode.DISABLED, null,
            Duration.ofSeconds(-1)));
  }

  @Test
  @DisplayName("PERSISTENT_FILE without path is rejected")
  void persistentWithoutPathRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new BootstrapConfiguration(BootstrapMode.PERSISTENT_FILE, null,
            BootstrapConfiguration.DEFAULT_VALIDITY));
  }

  @Test
  @DisplayName("DEFAULT_VALIDITY is 24 hours")
  void defaultValidityIs24Hours() {
    assertEquals(Duration.ofHours(24), BootstrapConfiguration.DEFAULT_VALIDITY);
  }
}
