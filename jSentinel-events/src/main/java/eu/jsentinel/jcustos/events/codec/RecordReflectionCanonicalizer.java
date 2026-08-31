package eu.jsentinel.jcustos.events.codec;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * Default {@link JSentinelEventCanonicalizer}: pulls the eight standard fields
 * from the event accessors and derives {@code attributes} by reflecting the
 * event's record components (skipping the {@code metadata} component, whose
 * contents are already represented by the standard fields).
 *
 * <p>Works for every framework event (all records) and for application events
 * declared as records. Non-record events contribute no extra attributes.
 * A {@code null} top-level component is omitted from the attribute map, and
 * nested record components render length-prefixed (R01) — see
 * {@code renderRecord} for the injectivity rationale.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class RecordReflectionCanonicalizer implements JSentinelEventCanonicalizer {

  /**
   * Marker emitted for a {@code null} nested-record component. It is emitted
   * bare — outside the length-prefixed {@code <utf8len>:value} form — so no
   * String value can collide with it: every non-null value carries its length
   * prefix (R01).
   */
  private static final String NULL_COMPONENT = "null";

  @Override
  public CanonicalJSentinelEventPayload canonicalize(JSentinelEvent event) {
    TreeMap<String, String> attributes = new TreeMap<>();
    if (event instanceof Record) {
      for (RecordComponent component : event.getClass().getRecordComponents()) {
        if ("metadata".equals(component.getName())) {
          continue;
        }
        Object value = readAccessor(event, component);
        if (value == null) {
          // R01: a null top-level component is OMITTED instead of rendering the
          // string "null" — presence vs. absence of the attribute key is
          // unambiguous in the encoded map, whereas the old "null" rendering
          // collided with a genuine "null" String value. Non-null values render
          // exactly as before, so flat-record payloads stay byte-identical.
          continue;
        }
        attributes.put(component.getName(), render(component.getName(), value));
      }
    }
    return new CanonicalJSentinelEventPayload(
        CanonicalJSentinelEventPayload.SCHEMA_VERSION,
        event.eventType().value(),
        event.eventId().value(),
        event.tenantId().value(),
        event.subjectId().value(),
        event.occurredAt().toString(),
        event.severity().name(),
        event.category().name(),
        attributes);
  }

  private static Object readAccessor(Object record, RecordComponent component) {
    try {
      return component.getAccessor().invoke(record);
    } catch (IllegalAccessException | InvocationTargetException e) {
      throw new PayloadCodecException(
          "Cannot read record component " + component.getName()
              + " of " + record.getClass().getName(), e);
    }
  }

  /**
   * Renders a single non-null component value to a deterministic string. R016:
   * only value-typed components whose textual form is stable across JVMs and
   * restarts are accepted. {@code String.valueOf} on an array / collection /
   * arbitrary object yields an identity hash ({@code [B@1a2b3c}) or an
   * order-dependent rendering, which would silently change the signature base
   * and break verification. Such components are rejected loudly instead.
   * {@code null} handling is the caller's concern (omission at top level, the
   * bare {@link #NULL_COMPONENT} marker inside nested-record framing).
   */
  private static String render(String componentName, Object value) {
    return switch (value) {
      case String s -> s;
      case Boolean b -> b.toString();
      case Character c -> c.toString();
      case Number n -> n.toString();
      case Enum<?> e -> e.name();
      case Record r -> renderRecord(r);
      default -> throw new PayloadCodecException(
          "record component '" + componentName + "' has non-canonicalizable type "
              + value.getClass().getName()
              + " — event record components must be String, Number, Boolean,"
              + " Character, enum, or a record composed of those (R016)");
    };
  }

  /**
   * Renders a nested value-record deterministically and injectively: components
   * sorted by name, each non-null value emitted length-prefixed as
   * {@code name=<utf8-byte-length>:value} (the same framing idea as the
   * envelope signature base), parts joined with {@code ';'} inside
   * {@code (...)}. The explicit byte length makes the rendering unambiguous for
   * any value content — a value containing {@code ';'} or {@code '='} cannot be
   * reframed as a different component set, closing the R01 collision where
   * {@code R(a="x;b=y", b="z")} and {@code R(a="x", b="y;b=z")} rendered
   * identically. A {@code null} component renders as the bare
   * {@code name=null} marker outside the length-prefixed form, which no String
   * value can produce (a genuine {@code "null"} String frames as
   * {@code name=4:null}).
   */
  private static String renderRecord(Record record) {
    TreeMap<String, String> parts = new TreeMap<>();
    for (RecordComponent component : record.getClass().getRecordComponents()) {
      Object value = readAccessor(record, component);
      parts.put(component.getName(), frame(component.getName(), value));
    }
    StringBuilder sb = new StringBuilder("(");
    boolean first = true;
    for (Map.Entry<String, String> e : parts.entrySet()) {
      if (!first) {
        sb.append(';');
      }
      first = false;
      sb.append(e.getKey()).append('=').append(e.getValue());
    }
    return sb.append(')').toString();
  }

  /** Frames one nested-record component value: bare null marker or length-prefixed rendering. */
  private static String frame(String componentName, Object value) {
    if (value == null) {
      return NULL_COMPONENT;
    }
    String rendered = render(componentName, value);
    int utf8Length = rendered.getBytes(StandardCharsets.UTF_8).length;
    return utf8Length + ":" + rendered;
  }
}
