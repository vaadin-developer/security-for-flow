package com.svenruppert.jsentinel.events.siem;

/*-
 * #%L
 * jSentinel Events — SIEM exporter
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

import com.svenruppert.jsentinel.events.testkit.TestkitEnvelopes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.Flushable;
import java.io.IOException;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SiemEventExporter — Appendable transport, isolation, line integrity")
class SiemEventExporterTest {

  @Test
  @DisplayName("writes one line per envelope and flushes each record by default")
  void writesLinePerEnvelope() {
    FlushCountingWriter out = new FlushCountingWriter();
    try (SiemEventExporter exporter = new SiemEventExporter(new CefEnvelopeFormatter(), out)) {
      exporter.onEnvelope(TestkitEnvelopes.envelope("env-a"));
      exporter.onEnvelope(TestkitEnvelopes.envelope("env-b"));

      String[] lines = out.delegate.toString().split("\n");
      assertEquals(2, lines.length);
      assertTrue(lines[0].contains("cs4=env-a"));
      assertTrue(lines[1].contains("cs4=env-b"));
      assertEquals(2, exporter.writtenCount());
      assertEquals(2, out.flushes.get(), "flush-each-record is the default");
    }
  }

  @Test
  @DisplayName("a broken transport is counted, never thrown, and recovery works")
  void brokenTransportIsolated() {
    ToggledFailingAppendable out = new ToggledFailingAppendable();
    SiemEventExporter exporter = new SiemEventExporter(new CefEnvelopeFormatter(), out);

    out.failing = true;
    assertDoesNotThrow(() -> exporter.onEnvelope(TestkitEnvelopes.envelope("env-fail")));
    assertEquals(1, exporter.failedCount());
    assertEquals(0, exporter.writtenCount());

    out.failing = false;
    exporter.onEnvelope(TestkitEnvelopes.envelope("env-ok"));
    assertEquals(1, exporter.writtenCount(), "a later good write still works");
  }

  @Test
  @DisplayName("concurrent publishes never interleave characters of two records")
  void concurrentLinesStayIntact() throws Exception {
    StringWriter out = new StringWriter();
    SiemEventExporter exporter =
        new SiemEventExporter(new JsonLinesEnvelopeFormatter(), out, false);

    Thread first = Thread.ofVirtual().start(() -> {
      for (int i = 0; i < 50; i++) {
        exporter.onEnvelope(TestkitEnvelopes.envelope("env-a-" + i));
      }
    });
    Thread second = Thread.ofVirtual().start(() -> {
      for (int i = 0; i < 50; i++) {
        exporter.onEnvelope(TestkitEnvelopes.envelope("env-b-" + i));
      }
    });
    first.join();
    second.join();

    String[] lines = out.toString().split("\n");
    assertEquals(100, lines.length);
    for (String line : lines) {
      assertTrue(line.startsWith("{") && line.endsWith("}"),
          "interleaved record detected: " + line);
    }
    assertEquals(100, exporter.writtenCount());
  }

  @Test
  @DisplayName("close flushes, is idempotent and does NOT close the caller's transport")
  void closeSemantics() {
    FlushCountingWriter out = new FlushCountingWriter();
    SiemEventExporter exporter =
        new SiemEventExporter(new CefEnvelopeFormatter(), out, false);
    exporter.onEnvelope(TestkitEnvelopes.envelope("env-close"));
    assertEquals(0, out.flushes.get());

    exporter.close();
    exporter.close();
    assertEquals(2, out.flushes.get(), "each close flushes; nothing else happens");
    assertDoesNotThrow(() -> out.delegate.append('x'),
        "the Appendable stays usable — its lifecycle belongs to the caller");
  }

  /** Real Flushable Appendable counting flushes — no mock framework. */
  private static final class FlushCountingWriter implements Appendable, Flushable {
    final StringWriter delegate = new StringWriter();
    final AtomicInteger flushes = new AtomicInteger();

    @Override
    public Appendable append(CharSequence csq) {
      return delegate.append(csq);
    }

    @Override
    public Appendable append(CharSequence csq, int start, int end) {
      return delegate.append(csq, start, end);
    }

    @Override
    public Appendable append(char c) {
      return delegate.append(c);
    }

    @Override
    public void flush() {
      flushes.incrementAndGet();
    }
  }

  /** Real Appendable whose failure mode can be toggled — no mock framework. */
  private static final class ToggledFailingAppendable implements Appendable {
    volatile boolean failing;

    @Override
    public Appendable append(CharSequence csq) throws IOException {
      if (failing) {
        throw new IOException("pipe closed");
      }
      return this;
    }

    @Override
    public Appendable append(CharSequence csq, int start, int end) throws IOException {
      return append(csq);
    }

    @Override
    public Appendable append(char c) throws IOException {
      return append(String.valueOf(c));
    }
  }
}
