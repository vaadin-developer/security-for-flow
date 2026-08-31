package eu.jsentinel.jcustos.events.rest;

/*-
 * #%L
 * jCustos Events — REST / SSE bridge
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

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * {@link SseSubscriber} backed by a bounded queue (Konzept §952 — backpressure
 * via a bounded per-connection queue). A full queue drops the frame instead of
 * blocking the broadcaster.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class BoundedQueueSseSubscriber implements SseSubscriber {

  /** Default per-connection queue capacity. */
  public static final int DEFAULT_CAPACITY = 1024;

  private final BlockingQueue<String> queue;

  public BoundedQueueSseSubscriber() {
    this(DEFAULT_CAPACITY);
  }

  public BoundedQueueSseSubscriber(int capacity) {
    this.queue = new ArrayBlockingQueue<>(capacity);
  }

  @Override
  public boolean offer(String frame) {
    return queue.offer(frame);
  }

  /**
   * Waits up to {@code timeout} for the next frame.
   *
   * @param timeout the wait duration
   * @param unit the time unit
   * @return the next frame, or {@code null} if none arrived in time
   * @throws InterruptedException if interrupted while waiting
   */
  public String poll(long timeout, TimeUnit unit) throws InterruptedException {
    return queue.poll(timeout, unit);
  }
}
