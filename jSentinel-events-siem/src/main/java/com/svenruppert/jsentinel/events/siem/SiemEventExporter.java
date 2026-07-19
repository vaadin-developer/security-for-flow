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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.audit.LogFieldScrubber;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.publisher.SignedEnvelopePublisher;

import java.io.Flushable;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link SignedEnvelopePublisher} that appends one formatted line per
 * envelope to a caller-supplied {@link Appendable}. Konzept goal 8
 * (V00.80.00): the framework ships <em>formatting only</em> — the consumer
 * owns the transport (file, socket, stdout, syslog pipe), which keeps the
 * module free of any SIEM vendor binding.
 * <p>
 * Writes are serialized on an internal lock so concurrent publishes cannot
 * interleave characters of two records. A write failure is counted and
 * logged (rate-limited, never the record content) and never propagates —
 * a broken SIEM pipe must not break the publish path.
 * {@link #close()} flushes but deliberately does NOT close the
 * {@code Appendable}: the consumer owns the transport's lifecycle.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class SiemEventExporter
    implements SignedEnvelopePublisher, HasLogger, AutoCloseable {

  /** Mirrors the drop-log policy of the SSE broadcaster (R041). */
  private static final int FAILURE_LOG_INTERVAL = 100;

  private final SiemEnvelopeFormatter formatter;
  private final Appendable out;
  private final boolean flushEachRecord;
  private final Object writeLock = new Object();
  private final AtomicLong written = new AtomicLong();
  private final AtomicLong failed = new AtomicLong();

  public SiemEventExporter(SiemEnvelopeFormatter formatter, Appendable out) {
    this(formatter, out, true);
  }

  /**
   * @param formatter       the record format (CEF, LEEF, JSON-lines, custom)
   * @param out             the transport, owned by the caller
   * @param flushEachRecord {@code true} flushes after every record when the
   *                        transport is {@link Flushable} — the safe default
   *                        for forensic streams; {@code false} leaves
   *                        buffering to the transport
   */
  public SiemEventExporter(SiemEnvelopeFormatter formatter, Appendable out,
      boolean flushEachRecord) {
    this.formatter = Objects.requireNonNull(formatter, "formatter");
    this.out = Objects.requireNonNull(out, "out");
    this.flushEachRecord = flushEachRecord;
  }

  @Override
  public void onEnvelope(SignedJSentinelEventEnvelope envelope) {
    if (envelope == null) {
      return;
    }
    try {
      String line = formatter.format(envelope);
      synchronized (writeLock) {
        out.append(line).append('\n');
        if (flushEachRecord && out instanceof Flushable flushable) {
          flushable.flush();
        }
      }
      written.incrementAndGet();
    } catch (IOException | RuntimeException ex) {
      long total = failed.incrementAndGet();
      if (total % FAILURE_LOG_INTERVAL == 1) {
        // Never the record content — it may carry subject data.
        logger().warn(
            "events-siem/write-failed: dropped the record for envelope {} ({}, total failed={})",
            LogFieldScrubber.scrub(envelope.envelopeId().value()),
            ex.getClass().getSimpleName(), total);
      }
    }
  }

  /** @return records successfully appended */
  public long writtenCount() {
    return written.get();
  }

  /** @return records lost to a formatter or transport failure */
  public long failedCount() {
    return failed.get();
  }

  /**
   * Flushes the transport when it is {@link Flushable}; idempotent; does
   * NOT close the {@code Appendable} — its lifecycle belongs to the caller.
   */
  @Override
  public void close() {
    synchronized (writeLock) {
      if (out instanceof Flushable flushable) {
        try {
          flushable.flush();
        } catch (IOException ex) {
          logger().warn("events-siem/close-flush-failed: {}",
              ex.getClass().getSimpleName());
        }
      }
    }
  }
}
