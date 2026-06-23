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

  private static String readComponent(JSentinelEvent event, RecordComponent component) {
    try {
      Object value = component.getAccessor().invoke(event);
      return String.valueOf(value);
    } catch (IllegalAccessException | InvocationTargetException e) {
      throw new PayloadCodecException(
          "Cannot read record component " + component.getName()
              + " of " + event.getClass().getName(), e);
    }
  }
}
