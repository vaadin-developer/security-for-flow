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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.TreeMap;

/**
 * Dependency-free file-based load/save of {@link CalibrationProfile}.
 *
 * <p>Profiles are written as Java {@link Properties} (UTF-8) with a
 * stable key ordering so the resulting file diffs cleanly across runs.
 * Parameter map entries are keyed as {@code param.<name>}; the
 * remaining metadata uses fixed top-level keys.</p>
 *
 * <p>Calibration is explicit: this store loads what the operator
 * persisted, it never recalibrates (CWE-754 / CWE-693).</p>
 */
public final class CalibrationProfileStore {

  private static final String KEY_ALGORITHM = "algorithm";
  private static final String KEY_PROVIDER_ID = "providerId";
  private static final String KEY_TARGET_MILLIS = "targetMillis";
  private static final String KEY_MEASURED_MILLIS = "measuredMillis";
  private static final String KEY_CALIBRATED_AT = "calibratedAt";
  private static final String PARAM_PREFIX = "param.";

  public CalibrationProfileStore() {
  }

  /**
   * Serialises the profile to the given path. Existing files are
   * overwritten atomically through {@link Files#move}.
   */
  public void save(CalibrationProfile profile, Path path) {
    Objects.requireNonNull(profile, "profile");
    Objects.requireNonNull(path, "path");

    // Sort keys for deterministic output.
    Map<String, String> sorted = new TreeMap<>();
    sorted.put(KEY_ALGORITHM, profile.algorithm());
    sorted.put(KEY_PROVIDER_ID, profile.providerId());
    sorted.put(KEY_TARGET_MILLIS, Long.toString(profile.targetMillis()));
    sorted.put(KEY_MEASURED_MILLIS, Long.toString(profile.measuredMillis()));
    sorted.put(KEY_CALIBRATED_AT, profile.calibratedAt().toString());
    for (Map.Entry<String, String> e : profile.parameters().entrySet()) {
      sorted.put(PARAM_PREFIX + e.getKey(), e.getValue());
    }

    try {
      Path parent = path.toAbsolutePath().getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
      try (BufferedWriter writer = Files.newBufferedWriter(
          tmp, StandardCharsets.UTF_8)) {
        writer.write("# CalibrationProfile (Phase 1a/1b)");
        writer.newLine();
        for (Map.Entry<String, String> e : sorted.entrySet()) {
          writer.write(e.getKey());
          writer.write('=');
          writer.write(e.getValue());
          writer.newLine();
        }
      }
      Files.move(tmp, path,
          java.nio.file.StandardCopyOption.REPLACE_EXISTING,
          java.nio.file.StandardCopyOption.ATOMIC_MOVE);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Deserialises a profile from the given path. Throws if the file is
   * missing or malformed; never silently substitutes defaults.
   */
  public CalibrationProfile load(Path path) {
    Objects.requireNonNull(path, "path");
    Properties properties = new Properties();
    try (BufferedReader reader = Files.newBufferedReader(
        path, StandardCharsets.UTF_8)) {
      properties.load(reader);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }

    String algorithm = requireString(properties, KEY_ALGORITHM);
    String providerId = requireString(properties, KEY_PROVIDER_ID);
    long targetMillis = requireLong(properties, KEY_TARGET_MILLIS);
    long measuredMillis = requireLong(properties, KEY_MEASURED_MILLIS);
    String calibratedAtRaw = requireString(properties, KEY_CALIBRATED_AT);
    Instant calibratedAt;
    try {
      calibratedAt = Instant.parse(calibratedAtRaw);
    } catch (DateTimeParseException dpe) {
      throw new IllegalArgumentException(
          "malformed calibratedAt: " + KEY_CALIBRATED_AT);
    }

    Map<String, String> parameters = new LinkedHashMap<>();
    for (String key : properties.stringPropertyNames()) {
      if (key.startsWith(PARAM_PREFIX)) {
        parameters.put(
            key.substring(PARAM_PREFIX.length()),
            properties.getProperty(key));
      }
    }
    return new CalibrationProfile(algorithm, providerId, parameters,
        targetMillis, measuredMillis, calibratedAt);
  }

  private static String requireString(Properties p, String key) {
    String v = p.getProperty(key);
    if (v == null || v.isBlank()) {
      throw new IllegalArgumentException(
          "missing calibration property: " + key);
    }
    return v;
  }

  private static long requireLong(Properties p, String key) {
    String v = requireString(p, key);
    try {
      return Long.parseLong(v);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          "calibration property is not a long: " + key);
    }
  }
}
