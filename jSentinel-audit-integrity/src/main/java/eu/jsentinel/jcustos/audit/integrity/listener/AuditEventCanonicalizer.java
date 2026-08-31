package eu.jsentinel.jcustos.audit.integrity.listener;

/*-
 * #%L
 * jCustos Audit Integrity — tamper-evident audit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainException;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.codec.CanonicalJson;

import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Deterministic canonical-JSON rendering of core {@link AuditEvent} records
 * for the hash chain. The events-module canonicalizer cannot serve here —
 * it requires the {@code JCustosEvent} accessors and its whitelist lacks
 * {@link Instant}/{@link Duration}, both of which audit records carry.
 * <p>
 * Shape: {@code {"v":1,"type":"<record simple name>","fields":{...}}} with
 * lexicographically sorted field names (the canonical-JSON writer sorts).
 * Rendering rules: strings verbatim; booleans, characters, numbers and
 * enums via {@code toString()}; {@link Instant} and {@link Duration} via
 * their stable ISO-8601 {@code toString()}; nested records recursively;
 * {@code null} components are omitted (presence vs. absence is
 * unambiguous). Any other component type fails loud — a silent
 * identity-hash rendering would break verification.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class AuditEventCanonicalizer {

  static final String CODE_NOT_CANONICALIZABLE =
      "audit-integrity/audit-event-not-canonicalizable";

  private static final long FORMAT_VERSION = 1L;
  private static final String F_VERSION = "v";
  private static final String F_TYPE = "type";
  private static final String F_FIELDS = "fields";

  private AuditEventCanonicalizer() {
  }

  /**
   * @param event the audit event
   * @return its deterministic canonical-JSON bytes
   * @throws AuditChainException code
   *     {@code audit-integrity/audit-event-not-canonicalizable} for a
   *     component type outside the documented whitelist
   */
  public static byte[] canonicalize(AuditEvent event) {
    Objects.requireNonNull(event, "event");
    Map<String, Object> document = new LinkedHashMap<>();
    document.put(F_VERSION, FORMAT_VERSION);
    document.put(F_TYPE, event.getClass().getSimpleName());
    document.put(F_FIELDS, renderRecord(event));
    StringBuilder out = new StringBuilder();
    CanonicalJson.write(out, document);
    return out.toString().getBytes(StandardCharsets.UTF_8);
  }

  // Package-private: the fail-loud whitelist is pinned by tests with local
  // records — the sealed AuditEvent hierarchy cannot carry a test-only type.
  static Map<String, Object> renderRecord(Object record) {
    Map<String, Object> fields = new LinkedHashMap<>();
    for (RecordComponent component : record.getClass().getRecordComponents()) {
      Object value;
      try {
        value = component.getAccessor().invoke(record);
      } catch (ReflectiveOperationException e) {
        throw new AuditChainException(CODE_NOT_CANONICALIZABLE,
            "cannot read component '" + component.getName() + "' of "
                + record.getClass().getSimpleName(), e);
      }
      if (value == null) {
        continue;
      }
      fields.put(component.getName(), render(component.getName(), value));
    }
    return fields;
  }

  private static Object render(String name, Object value) {
    return switch (value) {
      case String s -> s;
      case Instant instant -> instant.toString();
      case Duration duration -> duration.toString();
      case Boolean b -> b.toString();
      case Character c -> c.toString();
      case Number n -> n.toString();
      case Enum<?> constant -> constant.toString();
      case Record nested -> renderRecord(nested);
      default -> throw new AuditChainException(CODE_NOT_CANONICALIZABLE,
          "component '" + name + "' has unsupported type "
              + value.getClass().getName()
              + " — extend the whitelist deliberately, never silently");
    };
  }
}
