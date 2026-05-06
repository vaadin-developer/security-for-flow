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

import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BootstrapConfigurationLoader")
class BootstrapConfigurationLoaderTest {

  private final Map<String, String> sysprops = new HashMap<>();
  private final Map<String, String> env = new HashMap<>();
  private final BootstrapConfigurationLoader loader =
      new BootstrapConfigurationLoader(sysprops::get, env::get);

  @Test
  @DisplayName("returns the supplied default when nothing is configured")
  void defaults() {
    BootstrapConfiguration cfg = loader.load(
        BootstrapMode.DISABLED, Path.of("/tmp/unused"), Duration.ofHours(1));
    assertEquals(BootstrapMode.DISABLED, cfg.mode());
    assertEquals(Duration.ofHours(1), cfg.tokenValidity());
  }

  @Test
  @DisplayName("system property has precedence over environment variable")
  void sysPropOverridesEnv() {
    sysprops.put(BootstrapConfigurationLoader.MODE_PROPERTY, "TRANSIENT_CONSOLE");
    env.put(BootstrapConfigurationLoader.MODE_ENV, "PERSISTENT_FILE");
    BootstrapConfiguration cfg = loader.load(
        BootstrapMode.DISABLED, Path.of("/tmp/file"), Duration.ofHours(1));
    assertEquals(BootstrapMode.TRANSIENT_CONSOLE, cfg.mode());
  }

  @Test
  @DisplayName("environment variable is used when no system property is set")
  void envFallback() {
    env.put(BootstrapConfigurationLoader.MODE_ENV, "PERSISTENT_FILE");
    env.put(BootstrapConfigurationLoader.TOKEN_FILE_ENV, "/tmp/from-env.token");
    BootstrapConfiguration cfg = loader.load(
        BootstrapMode.DISABLED, Path.of("/tmp/default"), Duration.ofHours(1));
    assertEquals(BootstrapMode.PERSISTENT_FILE, cfg.mode());
    assertEquals(Path.of("/tmp/from-env.token"), cfg.tokenFilePath());
  }

  @Test
  @DisplayName("invalid mode value fails fast with IllegalArgumentException")
  void invalidMode() {
    sysprops.put(BootstrapConfigurationLoader.MODE_PROPERTY, "BOGUS");
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
        () -> loader.load(BootstrapMode.DISABLED, null, Duration.ofHours(1)));
    assertTrue(ex.getMessage().contains("BOGUS"));
  }

  @Test
  @DisplayName("ISO-8601 TTL overrides the default")
  void ttlOverride() {
    sysprops.put(BootstrapConfigurationLoader.MODE_PROPERTY, "TRANSIENT_CONSOLE");
    sysprops.put(BootstrapConfigurationLoader.TOKEN_TTL_PROPERTY, "PT15M");
    BootstrapConfiguration cfg = loader.load(
        BootstrapMode.DISABLED, null, Duration.ofHours(24));
    assertEquals(Duration.ofMinutes(15), cfg.tokenValidity());
  }

  @Test
  @DisplayName("invalid TTL value fails fast")
  void invalidTtl() {
    sysprops.put(BootstrapConfigurationLoader.TOKEN_TTL_PROPERTY, "15-minutes");
    assertThrows(IllegalArgumentException.class,
        () -> loader.load(BootstrapMode.TRANSIENT_CONSOLE, null, Duration.ofHours(24)));
  }

  @Test
  @DisplayName("zero or negative TTL is rejected")
  void nonPositiveTtl() {
    sysprops.put(BootstrapConfigurationLoader.TOKEN_TTL_PROPERTY, "PT0S");
    assertThrows(IllegalArgumentException.class,
        () -> loader.load(BootstrapMode.TRANSIENT_CONSOLE, null, Duration.ofHours(24)));
  }
}
