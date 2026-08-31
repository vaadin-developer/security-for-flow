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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.demo.rest.domain.DemoRole;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.ResourcePredicates;
import eu.jsentinel.jcustos.policy.api.SubjectPredicates;

/**
 * V00.70 Policy-DSL examples — currently a single named policy
 * {@code document.owner-or-admin} that fronts
 * {@code /api/owned-documents/{id}} and is hit by
 * {@code @RequiresPolicy("document.owner-or-admin")} on the
 * inspect-handler.
 * <p>
 * The DSL chain reads as a literal English sentence:
 * <pre>{@code
 *   allow if the subject has ROLE_ADMIN,
 *   or  if the resolved document's ownerId equals the subject id;
 *   deny otherwise.
 * }</pre>
 * Registered programmatically with
 * {@link eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver#policyRegistry()}
 * at {@code DemoRestServer} startup.
 */
public final class DemoPolicies {

  /** Policy name used by {@code @RequiresPolicy(...)} on the handler. */
  public static final String DOCUMENT_OWNER_OR_ADMIN = "document.owner-or-admin";

  private DemoPolicies() {
  }

  public static Policy documentOwnerOrAdmin() {
    return Policy.named(DOCUMENT_OWNER_OR_ADMIN)
        .allowIf(SubjectPredicates.hasRole(DemoRole.ROLE_ADMIN.name()))
        .orIf(ResourcePredicates.ownerMatchesSubject(
            DemoOwnedDocumentResolver.RESOURCE_TYPE,
            DemoOwnedDocumentResolver.OWNER_ATTRIBUTE))
        .deny("not document owner and not admin")
        .build();
  }
}
