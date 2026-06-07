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
package com.svenruppert.vaadin.security.demo.app.security.services;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.Secured;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;

import java.util.List;

/**
 * Demo wrapper around audit operations, exercised through the V00.70
 * Phase-6 {@code security-processor} compile-time annotation
 * processor. The {@link Secured @Secured} mark triggers code
 * generation: a {@code DemoAuditOperationsSecured} subclass is
 * emitted alongside this class, with each annotated method
 * delegating through {@code SecurityEnforcer} before invoking
 * {@code super.<method>(...)}.
 * <p>
 * Concrete-class flavour of the same demonstration that
 * {@code SecuredProxy.wrap(...)} handles for interfaces: callers
 * instantiate the generated {@code DemoAuditOperationsSecured} and
 * get permission enforcement transparently.
 * <p>
 * Demo only — production deployments would put real retention /
 * compliance operations behind permissions in the same shape.
 */
@Secured
public class DemoAuditOperations {

  /**
   * Read-only event listing — gated on {@code audit:read}, the
   * same permission that fronts {@code /audit} navigation.
   */
  @RequiresPermission("audit:read")
  public List<AuditEvent> listEvents() {
    SecurityAuditService audit = SecurityServiceResolver.securityAuditService();
    return audit.query(AuditQuery.all());
  }

  /**
   * Destructive retention sweep — requires <strong>both</strong>
   * {@code audit:read} (to first inventory what would be purged)
   * <em>and</em> {@code audit:purge} (the destructive operation
   * itself). Demonstrates the {@code @RequiresAllPermissions}
   * AND-semantics evaluator on a concrete-class-with-@Secured
   * surface.
   * <p>
   * The demo no-op implementation simply returns the would-be
   * deleted count without touching the underlying store, so an
   * exploratory click in the admin UI is safe.
   */
  @RequiresAllPermissions({"audit:read", "audit:purge"})
  public int purgeAuditOlderThanDays(int days) {
    if (days < 0) {
      throw new IllegalArgumentException("days must be non-negative");
    }
    SecurityAuditService audit = SecurityServiceResolver.securityAuditService();
    // Pretend purge: count events that would qualify. Production
    // code would actually drop them via AuditEventStore.purgeOlderThan.
    return audit.query(AuditQuery.all()).size();
  }
}
