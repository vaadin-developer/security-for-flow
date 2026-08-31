package eu.jsentinel.jcustos.audit.integrity.listener;

/*-
 * #%L
 * jSentinel Audit Integrity — tamper-evident audit
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

import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainAppender;
import eu.jsentinel.jcustos.audit.integrity.chain.InMemoryAuditChainStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.types.BusStartedEvent;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("AuditIntegrityListener + HashChainingAuditSink — chain feeds with strict isolation")
class AuditIntegrityListenerTest {

  private static final Instant AT = Instant.parse("2026-07-19T10:15:30Z");

  private final InMemoryAuditChainStore store = new InMemoryAuditChainStore();
  private final AuditIntegrityListener listener =
      new AuditIntegrityListener(new AuditChainAppender(store));

  private static LoginSucceededEvent loginEvent(JSentinelEventSeverity severity) {
    return new LoginSucceededEvent(
        EventMetadata.create(TenantId.DEFAULT, JSentinelEvent.SYSTEM_SUBJECT, AT, severity),
        "password");
  }

  @Test
  @DisplayName("audit-relevant events are chained and their payload decodes")
  void relevantEventChained() {
    listener.onJSentinelEvent(loginEvent(JSentinelEventSeverity.INFO));

    assertEquals(1, store.size(),
        "an AUTHENTICATION event is chained regardless of severity");
    AuditChainEntry entry = store.entryAt(0).orElseThrow();
    assertEquals(AuditIntegrityListener.PAYLOAD_TYPE, entry.payloadType());
    assertDoesNotThrow(() -> new CanonicalJsonPayloadCodec().decode(entry.payload()),
        "the chained payload must decode through the canonical codec");
  }

  @Test
  @DisplayName("DEBUG system noise stays out of the chain by default")
  void systemNoiseFiltered() {
    listener.onJSentinelEvent(new BusStartedEvent(EventMetadata.create(
        TenantId.DEFAULT, JSentinelEvent.SYSTEM_SUBJECT, AT,
        JSentinelEventSeverity.DEBUG)));

    assertEquals(0, store.size());
  }

  @Test
  @DisplayName("a full chain store never breaks the dispatch path")
  void fullStoreIsolated() {
    InMemoryAuditChainStore tiny = new InMemoryAuditChainStore(1);
    AuditIntegrityListener tinyListener =
        new AuditIntegrityListener(new AuditChainAppender(tiny));

    tinyListener.onJSentinelEvent(loginEvent(JSentinelEventSeverity.INFO));
    assertDoesNotThrow(() ->
        tinyListener.onJSentinelEvent(loginEvent(JSentinelEventSeverity.INFO)));
    assertEquals(1, tiny.size());
  }

  @Test
  @DisplayName("the audit sink chains core audit events and honors its never-throws contract")
  void auditSinkChainsAndIsolates() {
    HashChainingAuditSink sink = new HashChainingAuditSink(new AuditChainAppender(store));
    sink.accept(new LoginSucceeded(AT, "alice", "127.0.0.1", null));

    assertEquals(1, store.size());
    assertEquals(HashChainingAuditSink.PAYLOAD_TYPE_AUDIT,
        store.entryAt(0).orElseThrow().payloadType());

    InMemoryAuditChainStore tiny = new InMemoryAuditChainStore(1);
    HashChainingAuditSink tinySink = new HashChainingAuditSink(new AuditChainAppender(tiny));
    tinySink.accept(new LoginSucceeded(AT, "alice", "127.0.0.1", null));
    assertDoesNotThrow(() ->
        tinySink.accept(new LoginSucceeded(AT, "bob", "127.0.0.1", null)));
    assertEquals(1, tiny.size());
  }
}
