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
package eu.jsentinel.jcustos.audit;

import java.util.List;

/**
 * Default {@link JCustosAuditService} — discards every event and never
 * retains anything. Used when no SPI is registered and no application-level
 * audit sink is configured.
 */
public final class NoopJCustosAuditService implements JCustosAuditService {

  /** Singleton instance. */
  public static final NoopJCustosAuditService INSTANCE = new NoopJCustosAuditService();

  /** Public for {@link java.util.ServiceLoader} discovery. Prefer {@link #INSTANCE}. */
  public NoopJCustosAuditService() {
  }

  @Override
  public void publish(AuditEvent event) {
    // intentionally empty
  }

  @Override
  public List<AuditEvent> query(AuditQuery query) {
    return List.of();
  }
}
