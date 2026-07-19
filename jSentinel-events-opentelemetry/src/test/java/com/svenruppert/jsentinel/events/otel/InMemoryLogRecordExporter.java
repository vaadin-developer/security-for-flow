package com.svenruppert.jsentinel.events.otel;

/*-
 * #%L
 * jSentinel Events — OpenTelemetry exporter
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

import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Hand-written in-memory {@link LogRecordExporter} — a real exporter
 * implementation, not a mock ({@code opentelemetry-sdk-testing} is not on
 * the classpath by design).
 */
class InMemoryLogRecordExporter implements LogRecordExporter {

  private final List<LogRecordData> records =
      Collections.synchronizedList(new ArrayList<>());

  @Override
  public CompletableResultCode export(Collection<LogRecordData> logs) {
    records.addAll(logs);
    return CompletableResultCode.ofSuccess();
  }

  @Override
  public CompletableResultCode flush() {
    return CompletableResultCode.ofSuccess();
  }

  @Override
  public CompletableResultCode shutdown() {
    return CompletableResultCode.ofSuccess();
  }

  List<LogRecordData> records() {
    synchronized (records) {
      return List.copyOf(records);
    }
  }

  LogRecordData single() {
    List<LogRecordData> snapshot = records();
    if (snapshot.size() != 1) {
      throw new AssertionError("expected exactly one log record, got " + snapshot.size());
    }
    return snapshot.get(0);
  }
}
