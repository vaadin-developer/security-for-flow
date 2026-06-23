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
import com.svenruppert.jsentinel.events.api.PayloadContentType;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * Interoperable {@link PayloadCodec}: encodes a
 * {@link CanonicalJSentinelEventPayload} as canonical JSON (Konzept §431-§466)
 * via the in-tree {@link CanonicalJson} engine. This is the default,
 * REST/SSE-friendly, externally readable codec.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class CanonicalJsonPayloadCodec implements PayloadCodec {

  private static final String KEY_SCHEMA = "schemaVersion";
  private static final String KEY_EVENT_TYPE = "eventType";
  private static final String KEY_EVENT_ID = "eventId";
  private static final String KEY_TENANT_ID = "tenantId";
  private static final String KEY_SUBJECT_ID = "subjectId";
  private static final String KEY_OCCURRED_AT = "occurredAt";
  private static final String KEY_SEVERITY = "severity";
  private static final String KEY_CATEGORY = "category";
  private static final String KEY_ATTRIBUTES = "attributes";

  @Override
  public PayloadContentType contentType() {
    return PayloadContentType.CANONICAL_JSON;
  }

  @Override
  public byte[] encode(CanonicalJSentinelEventPayload payload) {
    Map<String, Object> root = new TreeMap<>();
    root.put(KEY_SCHEMA, payload.schemaVersion());
    root.put(KEY_EVENT_TYPE, payload.eventType());
    root.put(KEY_EVENT_ID, payload.eventId());
    root.put(KEY_TENANT_ID, payload.tenantId());
    root.put(KEY_SUBJECT_ID, payload.subjectId());
    root.put(KEY_OCCURRED_AT, payload.occurredAt());
    root.put(KEY_SEVERITY, payload.severity());
    root.put(KEY_CATEGORY, payload.category());
    root.put(KEY_ATTRIBUTES, new TreeMap<String, Object>(payload.attributes()));
    StringBuilder out = new StringBuilder();
    CanonicalJson.write(out, root);
    return out.toString().getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public CanonicalJSentinelEventPayload decode(byte[] bytes) {
    Object parsed = CanonicalJson.parse(new String(bytes, StandardCharsets.UTF_8));
    if (!(parsed instanceof Map<?, ?> map)) {
      throw new PayloadCodecException("canonical JSON payload must be a JSON object");
    }
    TreeMap<String, String> attributes = new TreeMap<>();
    Object rawAttributes = require(map, KEY_ATTRIBUTES);
    if (!(rawAttributes instanceof Map<?, ?> attrMap)) {
      throw new PayloadCodecException("'attributes' must be a JSON object");
    }
    for (Map.Entry<?, ?> e : attrMap.entrySet()) {
      attributes.put(String.valueOf(e.getKey()), asString(e.getValue(), "attribute"));
    }
    return new CanonicalJSentinelEventPayload(
        (int) asLong(require(map, KEY_SCHEMA)),
        asString(require(map, KEY_EVENT_TYPE), KEY_EVENT_TYPE),
        asString(require(map, KEY_EVENT_ID), KEY_EVENT_ID),
        asString(require(map, KEY_TENANT_ID), KEY_TENANT_ID),
        asString(require(map, KEY_SUBJECT_ID), KEY_SUBJECT_ID),
        asString(require(map, KEY_OCCURRED_AT), KEY_OCCURRED_AT),
        asString(require(map, KEY_SEVERITY), KEY_SEVERITY),
        asString(require(map, KEY_CATEGORY), KEY_CATEGORY),
        attributes);
  }

  private static Object require(Map<?, ?> map, String key) {
    Object value = map.get(key);
    if (value == null) {
      throw new PayloadCodecException("missing canonical payload field '" + key + "'");
    }
    return value;
  }

  private static String asString(Object value, String field) {
    if (!(value instanceof String s)) {
      throw new PayloadCodecException("field '" + field + "' must be a string");
    }
    return s;
  }

  private static long asLong(Object value) {
    if (!(value instanceof Long l)) {
      throw new PayloadCodecException("field 'schemaVersion' must be an integer");
    }
    return l;
  }
}
