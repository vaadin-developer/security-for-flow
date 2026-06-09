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
package com.svenruppert.vaadin.security.logout;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.session.JSentinelVersion;
import com.svenruppert.vaadin.security.session.JSentinelVersionKey;
import com.svenruppert.vaadin.security.session.JSentinelVersionStore;
import com.svenruppert.vaadin.security.session.SessionId;
import com.svenruppert.vaadin.security.session.SessionRecord;
import com.svenruppert.vaadin.security.session.SessionStatus;
import com.svenruppert.vaadin.security.session.SessionStore;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * {@link SubjectSessionRegistry} that stores its
 * (subject, sessionId) associations as full
 * {@link SessionRecord}s in a {@link SessionStore}.
 * <p>
 * The registry contract is narrower than what
 * {@code SessionStore} can represent — it does not track
 * {@code createdAt} / {@code lastActivityAt} / status — so this
 * adapter fills the missing fields with sensible defaults at
 * {@link #register(SubjectId, String) register} time:
 * timestamps from the supplied clock,
 * {@link JSentinelVersion#INITIAL} (or the subject's current
 * value when a {@link JSentinelVersionStore} is supplied), status
 * {@link SessionStatus#ACTIVE}. Calling
 * {@link #register(SubjectId, String) register} again for an
 * existing session id refreshes the {@code lastActivityAt} via
 * upsert (idempotent in observable effect, as the contract
 * requires).
 *
 * <p>Bound to one {@link TenantId} at construction. Multi-tenant
 * deployments instantiate one registry per tenant.
 *
 * <p>For Phase 4c (JSentinelVersionCheck-driven session refresh),
 * pass a {@link JSentinelVersionStore} so each fresh session
 * captures the subject's current security version as its
 * {@link SessionRecord#securityVersionAtLogin() snapshot}.
 * Without one, every snapshot defaults to
 * {@link JSentinelVersion#INITIAL} — fine for adapters that don't
 * enforce drift but useless for the Vaadin/REST drift interceptors.
 */
@ExperimentalJSentinelApi
public final class StoreBackedSubjectSessionRegistry implements SubjectSessionRegistry {

  private final SessionStore store;
  private final TenantId tenant;
  private final Clock clock;
  private final JSentinelVersionStore versionStore;

  /**
   * Builds a registry bound to {@link TenantId#DEFAULT} using a
   * system clock and no version-store integration — every new
   * session is recorded with {@link JSentinelVersion#INITIAL}.
   *
   * @param store backing session store; non-null
   */
  public StoreBackedSubjectSessionRegistry(SessionStore store) {
    this(store, TenantId.DEFAULT, Clock.systemUTC(), null);
  }

  /**
   * Version-store-free constructor.
   *
   * @param store  backing session store; non-null
   * @param tenant tenant scope; {@code null} becomes
   *               {@link TenantId#DEFAULT}
   * @param clock  time source; non-null
   */
  public StoreBackedSubjectSessionRegistry(SessionStore store,
                                           TenantId tenant,
                                           Clock clock) {
    this(store, tenant, clock, null);
  }

  /**
   * Full constructor.
   *
   * @param store        backing session store; non-null
   * @param tenant       tenant scope; {@code null} becomes
   *                     {@link TenantId#DEFAULT}
   * @param clock        time source; non-null
   * @param versionStore optional version store consulted at
   *                     register-time to capture the subject's
   *                     current {@link JSentinelVersion} as the
   *                     session snapshot; {@code null} falls back
   *                     to {@link JSentinelVersion#INITIAL}
   */
  public StoreBackedSubjectSessionRegistry(SessionStore store,
                                           TenantId tenant,
                                           Clock clock,
                                           JSentinelVersionStore versionStore) {
    this.store = requireNonNull(store, "store must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
    this.versionStore = versionStore;
  }

  @Override
  public void register(SubjectId subjectId, String sessionId) {
    requireNonNull(subjectId, "subjectId must not be null");
    SessionId sid = sessionIdFrom(sessionId);
    java.time.Instant now = clock.instant();
    SessionRecord existing = store.findById(sid).orElse(null);
    SessionRecord record = existing == null
        ? new SessionRecord(sid, subjectId, tenant, now, now,
            snapshotVersionFor(subjectId), SessionStatus.ACTIVE)
        : existing.withLastActivityAt(now);
    store.save(record);
  }

  private JSentinelVersion snapshotVersionFor(SubjectId subjectId) {
    if (versionStore == null) {
      return JSentinelVersion.INITIAL;
    }
    return versionStore.current(new JSentinelVersionKey(tenant, subjectId));
  }

  @Override
  public void unregister(SubjectId subjectId, String sessionId) {
    requireNonNull(subjectId, "subjectId must not be null");
    SessionId sid = sessionIdFrom(sessionId);
    store.findById(sid).ifPresent(record -> {
      if (record.subjectId().equals(subjectId)) {
        store.delete(sid);
      }
    });
  }

  @Override
  public Collection<String> sessionsOf(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    List<SessionRecord> records = store.findBySubject(tenant, subjectId);
    List<String> ids = new ArrayList<>(records.size());
    for (SessionRecord record : records) {
      if (record.status().isActive()) {
        ids.add(record.sessionId().value());
      }
    }
    return List.copyOf(ids);
  }

  @Override
  public Collection<String> clearAll(SubjectId subjectId) {
    requireNonNull(subjectId, "subjectId must not be null");
    List<SessionRecord> records = store.findBySubject(tenant, subjectId);
    List<String> removed = new ArrayList<>(records.size());
    for (SessionRecord record : records) {
      if (store.delete(record.sessionId())) {
        removed.add(record.sessionId().value());
      }
    }
    return List.copyOf(removed);
  }

  private static SessionId sessionIdFrom(String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      throw new IllegalArgumentException("sessionId must not be blank");
    }
    return new SessionId(sessionId);
  }
}
