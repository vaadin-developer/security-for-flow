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
package com.svenruppert.jsentinel.rest;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.session.JSentinelVersion;

import static java.util.Objects.requireNonNull;

/**
 * Per-request session security context surfaced by a
 * {@link RestSubjectResolver} so {@link RestJSentinelVersionFilter}
 * can run a drift check before authorization.
 * <p>
 * Implementations of {@code RestSubjectResolver} that want their
 * deployment to participate in Phase 4c drift detection override
 * {@link RestSubjectResolver#resolveJSentinelVersionContext(RestRequest)}
 * and return a populated record. Implementations that don't (e.g.
 * stateless API-key flows where every request rehydrates the
 * subject) keep the default {@code Optional.empty()} and the
 * filter is a no-op for them.
 *
 * @param subjectId authenticated subject; non-null
 * @param tenant    tenant scope; {@code null} becomes
 *                  {@link TenantId#DEFAULT}
 * @param snapshot  security version captured when the session /
 *                  token was issued; non-null
 * @param sessionId opaque session identifier (token, session id, …)
 *                  for audit correlation; may be {@code null}
 */
@ExperimentalJSentinelApi
public record RestJSentinelVersionContext(
    SubjectId subjectId,
    TenantId tenant,
    JSentinelVersion snapshot,
    String sessionId
) {

  /** Validates the components and normalises {@code null} tenant. */
  public RestJSentinelVersionContext {
    requireNonNull(subjectId, "subjectId must not be null");
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(snapshot, "snapshot must not be null");
  }
}
