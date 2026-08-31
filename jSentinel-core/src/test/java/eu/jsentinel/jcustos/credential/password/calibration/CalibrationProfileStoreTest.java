/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.password.calibration;

import eu.jsentinel.jcustos.credential.password.pbkdf2.Pbkdf2ParameterNames;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CalibrationProfileStoreTest {

  private final CalibrationProfileStore store = new CalibrationProfileStore();

  private static CalibrationProfile sampleProfile() {
    Map<String, String> params = new LinkedHashMap<>();
    params.put(Pbkdf2ParameterNames.ITERATIONS, "750000");
    params.put(Pbkdf2ParameterNames.KEY_LENGTH, "32");
    return new CalibrationProfile(
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        params,
        250L,
        247L,
        Instant.parse("2026-06-01T12:34:56Z"));
  }

  @Test
  @DisplayName("save followed by load reproduces the same profile")
  void roundtrip(@TempDir Path tmp) {
    Path file = tmp.resolve("profile.properties");
    CalibrationProfile original = sampleProfile();
    store.save(original, file);
    CalibrationProfile reloaded = store.load(file);
    assertEquals(original, reloaded);
  }

  @Test
  @DisplayName("Saved file is deterministic across saves (no spurious diffs)")
  void deterministicSerialisation(@TempDir Path tmp) throws Exception {
    Path file = tmp.resolve("profile.properties");
    CalibrationProfile profile = sampleProfile();
    store.save(profile, file);
    String first = Files.readString(file);
    store.save(profile, file);
    String second = Files.readString(file);
    assertEquals(first, second,
        "two saves of the same profile must produce byte-identical files");
  }

  @Test
  @DisplayName("load rejects a missing file with UncheckedIOException")
  void missingFileRejected(@TempDir Path tmp) {
    Path file = tmp.resolve("absent.properties");
    assertThrows(RuntimeException.class, () -> store.load(file));
  }

  @Test
  @DisplayName("load rejects a malformed file without substituting defaults (CWE-754)")
  void malformedFileRejected(@TempDir Path tmp) throws Exception {
    Path file = tmp.resolve("broken.properties");
    Files.writeString(file, "algorithm=PBKDF2WithHmacSHA256\n");
    // missing providerId / targetMillis / measuredMillis / calibratedAt
    assertThrows(IllegalArgumentException.class, () -> store.load(file));
  }

  @Test
  @DisplayName("load rejects a malformed calibratedAt timestamp")
  void malformedTimestampRejected(@TempDir Path tmp) throws Exception {
    Path file = tmp.resolve("badts.properties");
    Files.writeString(file,
        "algorithm=PBKDF2WithHmacSHA256\n"
            + "providerId=pbkdf2-jdk\n"
            + "targetMillis=250\n"
            + "measuredMillis=247\n"
            + "calibratedAt=not-an-instant\n"
            + "param.i=750000\n");
    assertThrows(IllegalArgumentException.class, () -> store.load(file));
  }

  @Test
  @DisplayName("Reloading the same profile twice yields the exact same parameters (no auto-recalibration)")
  void noAutoRecalibrationOnReload(@TempDir Path tmp) {
    Path file = tmp.resolve("stable.properties");
    CalibrationProfile profile = sampleProfile();
    store.save(profile, file);
    CalibrationProfile first = store.load(file);
    CalibrationProfile second = store.load(file);
    assertEquals(first.parameters(), second.parameters());
    assertEquals(first.calibratedAt(), second.calibratedAt(),
        "loading must never overwrite calibratedAt with 'now'");
  }

  @Test
  @DisplayName("CalibrationProfile rejects blank algorithm / non-positive targetMillis")
  void invariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new CalibrationProfile(" ", "pbkdf2-jdk",
            Map.of("i", "1000"), 100L, 90L, Instant.now()));
    assertThrows(IllegalArgumentException.class,
        () -> new CalibrationProfile("PBKDF2WithHmacSHA256", "pbkdf2-jdk",
            Map.of("i", "1000"), 0L, 90L, Instant.now()));
  }

  @Test
  @DisplayName("Parameter map of a saved profile is unmodifiable after roundtrip")
  void parametersUnmodifiable(@TempDir Path tmp) {
    Path file = tmp.resolve("p.properties");
    store.save(sampleProfile(), file);
    CalibrationProfile reloaded = store.load(file);
    assertThrows(UnsupportedOperationException.class,
        () -> reloaded.parameters().put("evil", "x"));
    assertTrue(reloaded.parameters().containsKey(Pbkdf2ParameterNames.ITERATIONS));
  }
}
