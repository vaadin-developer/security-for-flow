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
package com.svenruppert.jsentinel.demo.rest.domain;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory store for the V00.70 Policy-DSL demo. Seeded with one
 * doc per demo user so the {@code document.owner-or-admin} test can
 * exercise own-doc / foreign-doc / admin paths against a real
 * non-empty inventory.
 */
public final class DemoOwnedDocumentStore {

  private final Map<Long, DemoOwnedDocument> documents = new LinkedHashMap<>();
  private final AtomicLong nextId = new AtomicLong(1);

  public DemoOwnedDocumentStore() {
    create("Editor's notes", "editor");
    create("Viewer's wishlist", "viewer");
    create("Admin briefing", "admin");
  }

  public synchronized DemoOwnedDocument create(String title, String ownerId) {
    long id = nextId.getAndIncrement();
    DemoOwnedDocument doc = new DemoOwnedDocument(id, title, ownerId);
    documents.put(id, doc);
    return doc;
  }

  public synchronized Optional<DemoOwnedDocument> findById(long id) {
    return Optional.ofNullable(documents.get(id));
  }
}
