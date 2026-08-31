package eu.jsentinel.jcustos.events.codec;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Controlled, deterministic canonical representation of a security event
 * (Konzept §414-§429). Codecs serialize <em>this</em> model, never an
 * arbitrary {@code JCustosEvent} implementation, so the signature base stays
 * stable, versionable and testable.
 *
 * <p>The standard envelope-visible fields are explicit; the event-specific
 * payload lives in {@link #attributes()}, a key-sorted string map so two codec
 * runs over the same event produce identical bytes.
 *
 * @param schemaVersion explicit schema version (Konzept §464)
 * @param eventType the event type wire name
 * @param eventId the business event id
 * @param tenantId the tenant id value
 * @param subjectId the subject id value
 * @param occurredAt ISO-8601 UTC instant string
 * @param severity severity enum name
 * @param category category enum name
 * @param attributes key-sorted event-specific attributes (no nulls)
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record CanonicalJCustosEventPayload(
    int schemaVersion,
    String eventType,
    String eventId,
    String tenantId,
    String subjectId,
    String occurredAt,
    String severity,
    String category,
    SortedMap<String, String> attributes
) {

  /** Current canonical schema version. */
  public static final int SCHEMA_VERSION = 1;

  public CanonicalJCustosEventPayload {
    Objects.requireNonNull(eventType, "eventType");
    Objects.requireNonNull(eventId, "eventId");
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(occurredAt, "occurredAt");
    Objects.requireNonNull(severity, "severity");
    Objects.requireNonNull(category, "category");
    Objects.requireNonNull(attributes, "attributes");
    // defensive, deterministic copy: sorted, immutable
    attributes = new TreeMap<>(attributes);
    for (Map.Entry<String, String> e : attributes.entrySet()) {
      Objects.requireNonNull(e.getKey(), "attribute key");
      Objects.requireNonNull(e.getValue(), "attribute value for " + e.getKey());
    }
  }

  @Override
  public SortedMap<String, String> attributes() {
    return new TreeMap<>(attributes);
  }
}
