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
package eu.jsentinel.jcustos.demo.app.security.services;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditEventStore;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.InMemoryAuditEventStore;
import eu.jsentinel.jcustos.audit.LoggingAuditSink;
import eu.jsentinel.jcustos.audit.JCustosAuditService;
import eu.jsentinel.jcustos.audit.StoreBackedJCustosAuditService;

import java.util.List;

/**
 * Demo {@link JCustosAuditService} that swaps the framework's default
 * ring-buffer service for the V00.70 Phase-2
 * {@link StoreBackedJCustosAuditService} so audit events flow through
 * the {@link AuditEventStore} SPI — the same path a production
 * deployment with a persistent store (e.g. Eclipse-Store) would take.
 * <p>
 * Composition:
 * <ul>
 *   <li>{@link InMemoryAuditEventStore} — the persistent in-memory
 *       backing store wired into {@link StoreBackedJCustosAuditService}.</li>
 *   <li>{@link LoggingAuditSink} — a side-channel that mirrors every
 *       event to {@code java.util.logging}, matching the visibility
 *       of the framework default.</li>
 * </ul>
 *
 * <p>Unlike {@code DefaultCompositeAuditService}, this service does
 * <em>not</em> drop oldest events under load: the
 * {@link InMemoryAuditEventStore} keeps every event for the JVM
 * lifetime. Apps that need bounded retention would instead inject a
 * persistent store with its own {@code purgeOlderThan(...)} schedule.
 *
 * <p>Registered via {@code META-INF/services/eu.jsentinel.jcustos.audit.JCustosAuditService}.
 */
public final class DemoCompositeAuditService implements JCustosAuditService {

  private final StoreBackedJCustosAuditService persistentDelegate;
  private final LoggingAuditSink loggingSink;
  private final AuditEventStore store;

  public DemoCompositeAuditService() {
    this(new InMemoryAuditEventStore());
  }

  public DemoCompositeAuditService(AuditEventStore store) {
    this.store = store;
    this.persistentDelegate = new StoreBackedJCustosAuditService(store);
    this.loggingSink = new LoggingAuditSink();
  }

  @Override
  public void publish(AuditEvent event) {
    if (event == null) {
      return;
    }
    persistentDelegate.publish(event);
    try {
      loggingSink.accept(event);
    } catch (RuntimeException ignored) {
      // logging side-channel failure must never break the security flow
    }
  }

  @Override
  public List<AuditEvent> query(AuditQuery query) {
    return persistentDelegate.query(query);
  }

  /** Exposed so tests can verify direct store interaction without going through query. */
  public AuditEventStore store() {
    return store;
  }
}
