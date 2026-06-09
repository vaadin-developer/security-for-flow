/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.audit;

import java.util.List;

/**
 * No-arg {@link JSentinelAuditService} suitable for {@code META-INF/services}
 * registration. Combines a default-sized {@link RingBufferAuditSink} (for
 * {@link #query(AuditQuery)}) with a {@link LoggingAuditSink} that mirrors
 * every event to {@code java.util.logging} at {@code INFO}.
 * <p>
 * Applications that want different retention or additional sinks should
 * register their own {@code JSentinelAuditService} implementation instead
 * of this default.
 */
public final class DefaultCompositeAuditService implements JSentinelAuditService {

  private final CompositeAuditService delegate;

  public DefaultCompositeAuditService() {
    this.delegate = new CompositeAuditService(
        new RingBufferAuditSink(),
        new LoggingAuditSink());
  }

  @Override
  public void publish(AuditEvent event) {
    delegate.publish(event);
  }

  @Override
  public List<AuditEvent> query(AuditQuery query) {
    return delegate.query(query);
  }

  /** Exposed so a Vaadin {@code /audit}-route can read the ring buffer directly. */
  public RingBufferAuditSink ringBuffer() {
    return delegate.ringBuffer();
  }
}
