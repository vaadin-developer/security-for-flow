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
package eu.jsentinel.jcustos.demo.restclient.security.resource;

/**
 * Local in-memory document fixture used by the Resource-Based
 * Authorization demo. Carries only the fields a policy needs to
 * reason about — the demo deliberately does <strong>not</strong>
 * round-trip through the backend, because the point of this view is
 * the client-side admission mechanism, not the REST integration.
 *
 * @param id      stable document id
 * @param title   human-readable title (display only)
 * @param ownerId {@link eu.jsentinel.jcustos.demo.restclient.backend.RemoteUser#subjectId() RemoteUser.subjectId}
 *                of the owner; consumed by
 *                {@code ResourcePredicates.ownerMatchesSubject(...)}
 */
public record DemoDocument(String id, String title, String ownerId) {
}
