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
package com.svenruppert.vaadin.security.demo.rest.domain;

/**
 * Demo document variant with an explicit owner field, used by the
 * V00.70 Policy-DSL {@code document.owner-or-admin} example.
 * The plain {@link DemoDocument} stays owner-less so the existing
 * permission-only handlers don't need to grow an ownership concept.
 *
 * @param id      stable id
 * @param title   human-readable title
 * @param ownerId subjectId of the owner (matches
 *                {@code JSentinelSubject.subjectId()})
 */
public record DemoOwnedDocument(long id, String title, String ownerId) {
}
