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
package com.svenruppert.jsentinel.demo.restclient.security.resource;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Process-wide demo fixture: a small set of {@link DemoDocument}s
 * with hard-coded {@code ownerId}s so the Resource-Based Authorization
 * view can show owner-match against the currently signed-in subject.
 *
 * <p>The owner ids match the {@code subjectId}s returned by the
 * demo-rest backend for the seed accounts (admin, editor, viewer).
 * The view also includes a document owned by an unknown id so the
 * "non-owner, non-admin → deny" branch is reachable for every login.
 */
public final class DemoDocumentStore {

  private static final Map<String, DemoDocument> DOCUMENTS = new LinkedHashMap<>();

  static {
    add(new DemoDocument("doc-1", "Quarterly report (owned by admin)", "admin"));
    add(new DemoDocument("doc-2", "Editorial notes (owned by editor)", "editor"));
    add(new DemoDocument("doc-3", "Reading list (owned by viewer)", "viewer"));
    add(new DemoDocument("doc-4", "Stranger draft (owned by unknown-user)", "unknown-user"));
  }

  private DemoDocumentStore() {
  }

  /**
   * Returns the demo documents in registration order.
   *
   * @return immutable list of demo documents
   */
  public static List<DemoDocument> all() {
    return List.copyOf(DOCUMENTS.values());
  }

  /**
   * Looks up a demo document by id.
   *
   * @param id document id; {@code null} returns empty
   * @return document, or empty
   */
  public static Optional<DemoDocument> find(String id) {
    if (id == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(DOCUMENTS.get(id));
  }

  private static void add(DemoDocument doc) {
    DOCUMENTS.put(doc.id(), doc);
  }
}
