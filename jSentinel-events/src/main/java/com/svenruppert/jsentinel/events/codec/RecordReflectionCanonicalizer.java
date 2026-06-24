package com.svenruppert.jsentinel.events.codec;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.RecordComponent;
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
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class RecordReflectionCanonicalizer implements JSentinelEventCanonicalizer {

  @Override
  public CanonicalJSentinelEventPayload canonicalize(JSentinelEvent event) {
    TreeMap<String, String> attributes = new TreeMap<>();
    if (event instanceof Record) {
      for (RecordComponent component : event.getClass().getRecordComponents()) {
        if ("metadata".equals(component.getName())) {
          continue;
        }
        attributes.put(component.getName(), readComponent(event, component));
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

  private static String readComponent(Object record, RecordComponent component) {
    return render(component.getName(), readAccessor(record, component));
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
   * Renders a single component value to a deterministic string. R016: only
   * value-typed components whose textual form is stable across JVMs and restarts
   * are accepted. {@code String.valueOf} on an array / collection / arbitrary
   * object yields an identity hash ({@code [B@1a2b3c}) or an order-dependent
   * rendering, which would silently change the signature base and break
   * verification. Such components are rejected loudly instead.
   */
  private static String render(String componentName, Object value) {
    return switch (value) {
      case null -> "null";
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
   * Renders a nested value-record deterministically: components sorted by name,
   * each rendered recursively, as {@code (name=value;…)}.
   */
  private static String renderRecord(Record record) {
    TreeMap<String, String> parts = new TreeMap<>();
    for (RecordComponent component : record.getClass().getRecordComponents()) {
      parts.put(component.getName(), readComponent(record, component));
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
}
