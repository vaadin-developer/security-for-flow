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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import static java.util.Objects.requireNonNull;

/**
 * Composite key under which {@link JCustosVersionStore} tracks the
 * current {@link JCustosVersion} of a subject.
 * <p>
 * Tenant-aware: the same {@link SubjectId} can have an independent
 * version per tenant. A role change in one tenant must not invalidate
 * the subject's sessions in another tenant, which is what the planned
 * {@code JCustosVersionCheck} interceptor relies on.
 *
 * @param tenant    tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param subjectId subject identifier; non-null
 */
@ExperimentalJCustosApi
public record JCustosVersionKey(TenantId tenant, SubjectId subjectId) {

  /**
   * Validates the record components and normalises a {@code null}
   * tenant to {@link TenantId#DEFAULT}.
   *
   * @param tenant    tenant scope; {@code null} becomes DEFAULT
   * @param subjectId non-null subject id
   */
  public JCustosVersionKey {
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    requireNonNull(subjectId, "subjectId must not be null");
  }
}
