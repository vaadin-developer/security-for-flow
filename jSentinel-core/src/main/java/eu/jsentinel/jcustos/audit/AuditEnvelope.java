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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import static java.util.Objects.requireNonNull;

/**
 * Persisted form of an {@link AuditEvent}. Pairs the event with a
 * store-assigned identifier and the tenant scope so a queryable audit
 * store can return events that survived past one in-process buffer.
 * <p>
 * The {@code id} is opaque to the framework: implementations of
 * {@code AuditEventStore} are free to use UUIDs, monotonic counters,
 * or any other stable identifier — the only contract is that
 * {@code id} uniquely identifies the envelope within the store.
 *
 * @param id     non-blank store-assigned identifier
 * @param tenant tenant scope of the event; {@code null} becomes
 *               {@link TenantId#DEFAULT}
 * @param event  the wrapped audit event; never {@code null}
 */
@ExperimentalJSentinelApi
public record AuditEnvelope(String id, TenantId tenant, AuditEvent event) {

  /**
   * Validates the record components and substitutes
   * {@link TenantId#DEFAULT} for a {@code null} tenant.
   *
   * @param id     non-blank store-assigned identifier
   * @param tenant tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   * @param event  non-null audit event
   */
  public AuditEnvelope {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("id must not be blank");
    }
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(event, "event must not be null");
  }
}
