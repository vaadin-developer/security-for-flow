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
package eu.jsentinel.jcustos.demo.rest.domain;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** In-memory demo document store. */
public final class DemoDocumentStore {

  private final Map<Long, DemoDocument> documents = new LinkedHashMap<>();
  private final AtomicLong nextId = new AtomicLong(1);

  public DemoDocumentStore() {
    create("Welcome");
    create("Sample document");
  }

  public synchronized List<DemoDocument> list() {
    return List.copyOf(documents.values());
  }

  public synchronized DemoDocument create(String title) {
    long id = nextId.getAndIncrement();
    DemoDocument doc = new DemoDocument(id, title);
    documents.put(id, doc);
    return doc;
  }

  public synchronized boolean delete(long id) {
    return documents.remove(id) != null;
  }

  public synchronized Collection<DemoDocument> all() {
    return List.copyOf(documents.values());
  }
}
