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
package com.svenruppert.jsentinel.dx.runtime;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.dx.runtime.internal.JsonEncoder;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Result object returned by every adapter facade's {@code install()} call.
 * Lists every service the bootstrap registered, every diagnostic warning
 * the run accumulated and the operating mode that produced it.
 * <p>
 * Both {@link #services()} and {@link #warnings()} are unmodifiable.
 *
 * @since 00.72.00
 * @apiNote V00.73 — promoted to stable. Record shape and accessor set
 *          are unchanged since V00.72; additions remain non-breaking
 *          (record components cannot be removed without a SemVer bump).
 *          V00.74.10 — adds four instance methods ({@link #summary()},
 *          {@link #toMap()}, {@link #toJson()}, {@link #healthCheck()})
 *          marked {@link ExperimentalJSentinelApi}. The record components
 *          stay byte-compatible.
 */
public record JSentinelRuntime(
    List<RegisteredJSentinelService> services,
    List<JSentinelBootstrapWarning> warnings,
    JSentinelBootstrapMode mode) {

  public JSentinelRuntime {
    Objects.requireNonNull(services, "services");
    Objects.requireNonNull(warnings, "warnings");
    Objects.requireNonNull(mode, "mode");
    services = List.copyOf(services);
    warnings = List.copyOf(warnings);
  }

  /**
   * Renders this runtime as a multiline human-readable string suitable
   * for logging at application startup. Contains only metadata
   * (SPI/impl class names, warning codes); never includes credentials,
   * tokens, pepper key material or anything user-supplied beyond the
   * stable {@code source} strings.
   *
   * @return non-null multiline string ending with a final newline
   */
  public String log() {
    StringBuilder sb = new StringBuilder();
    sb.append("Security bootstrap diagnostics:\n");
    sb.append(" - mode = ").append(mode).append('\n');
    if (services.isEmpty()) {
      sb.append(" - services: (none)\n");
    } else {
      sb.append(" - services:\n");
      for (RegisteredJSentinelService s : services) {
        sb.append("    * ").append(s.spi().getSimpleName())
            .append(": ").append(s.impl().getName())
            .append(" (").append(s.source());
        if (s.defaulted()) {
          sb.append(", default");
        }
        sb.append(")\n");
      }
    }
    sb.append(" - Warnings: ").append(warnings.size()).append('\n');
    for (JSentinelBootstrapWarning w : warnings) {
      sb.append("    * [").append(w.severity()).append("] ")
          .append(w.code()).append(": ").append(w.message()).append('\n');
    }
    return sb.toString();
  }

  /**
   * One-line aggregated status suitable for a CLI banner, {@code /health}
   * preview, or boot banner. Format:
   * <pre>{@code <status> | <N> services | <E> errors | <W> warnings | <I> INFO}</pre>
   * where {@code <status>} is {@code OK} when no {@link Severity#ERROR}
   * warnings exist and {@code FAIL} otherwise.
   * <p>
   * The format is informal and may shift across releases. Consumers that
   * need machine-stable output should use {@link #toMap()} or
   * {@link #toJson()} instead.
   *
   * @return non-null status line, without a trailing newline
   * @since 00.74.10
   */
  @ExperimentalJSentinelApi
  public String summary() {
    long errors = warnings.stream().filter(w -> w.severity() == Severity.ERROR).count();
    long warns = warnings.stream().filter(w -> w.severity() == Severity.WARNING).count();
    long infos = warnings.stream().filter(w -> w.severity() == Severity.INFO).count();
    String status = errors == 0 ? "OK" : "FAIL";
    return status
        + " | " + services.size() + " services"
        + " | " + errors + " errors"
        + " | " + warns + " warnings"
        + " | " + infos + " INFO";
  }

  /**
   * Immutable nested-map view of this runtime. Keys (in insertion order):
   * {@code mode}, {@code serviceCount}, {@code services}, {@code warningCount},
   * {@code warnings}. The output is the canonical data source for
   * {@link #toJson()} and for consumer-side serialisation through any other
   * JSON library.
   * <p>
   * Pure function of this record's contents — repeated calls return equal
   * maps.
   *
   * @return non-null unmodifiable map preserving deterministic key order
   * @since 00.74.10
   */
  @ExperimentalJSentinelApi
  public Map<String, Object> toMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("mode", mode.name());
    out.put("serviceCount", services.size());
    out.put("services", services.stream()
        .map(JSentinelRuntime::serviceToMap)
        .toList());
    out.put("warningCount", warnings.size());
    out.put("warnings", warnings.stream()
        .map(JSentinelRuntime::warningToMap)
        .toList());
    return Collections.unmodifiableMap(out);
  }

  /**
   * Compact JSON serialisation of {@link #toMap()}.
   * <p>
   * The encoder is an internal RFC 8259 implementation; no Jackson or Gson
   * dependency is pulled in. Use this when wiring a minimal
   * {@code /health} endpoint and your project does not already carry a
   * JSON library on the runtime classpath.
   *
   * @return non-null JSON string
   * @since 00.74.10
   */
  @ExperimentalJSentinelApi
  public String toJson() {
    return JsonEncoder.encode(toMap());
  }

  /**
   * Structured health classification — the canonical {@code /health}
   * endpoint return type. Pure function of {@link #warnings()} plus a
   * single wall-clock stamp on {@link HealthStatus#inspectedAt()}.
   * <p>
   * Severity → overall classification:
   * <ul>
   *   <li>{@link Severity#ERROR} present ⇒ {@link Health#FAILED}.
   *   <li>{@link Severity#WARNING} present (no errors) ⇒ {@link Health#DEGRADED}.
   *   <li>Only {@link Severity#INFO} findings (or none) ⇒ {@link Health#HEALTHY}.
   * </ul>
   * INFO findings are intentionally non-degrading — they are
   * diagnostic-only.
   *
   * @return non-null health status snapshot
   * @since 00.74.10
   */
  @ExperimentalJSentinelApi
  public HealthStatus healthCheck() {
    List<HealthFinding> findings = warnings.stream()
        .map(w -> new HealthFinding(w.severity(), w.code(), w.message()))
        .toList();
    boolean anyError = findings.stream().anyMatch(f -> f.severity() == Severity.ERROR);
    boolean anyWarning = findings.stream().anyMatch(f -> f.severity() == Severity.WARNING);
    Health overall = anyError ? Health.FAILED : (anyWarning ? Health.DEGRADED : Health.HEALTHY);
    return new HealthStatus(overall, findings, services.size(), Instant.now());
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static Map<String, Object> serviceToMap(RegisteredJSentinelService s) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("spi", s.spi().getName());
    m.put("impl", s.impl().getName());
    m.put("source", s.source());
    m.put("defaulted", s.defaulted());
    return Collections.unmodifiableMap(m);
  }

  private static Map<String, Object> warningToMap(JSentinelBootstrapWarning w) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("severity", w.severity().name());
    m.put("code", w.code());
    m.put("message", w.message());
    m.put("suggestedFix", w.suggestedFix());
    return Collections.unmodifiableMap(m);
  }
}
