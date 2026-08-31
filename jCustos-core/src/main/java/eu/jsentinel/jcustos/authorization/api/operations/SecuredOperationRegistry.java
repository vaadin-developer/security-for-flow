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
package eu.jsentinel.jcustos.authorization.api.operations;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Registry of {@link SecuredOperationDescriptor}s, looked up by id. */
public final class SecuredOperationRegistry {

  private final Map<String, SecuredOperationDescriptor> byId = new LinkedHashMap<>();

  public synchronized void register(SecuredOperationDescriptor descriptor) {
    Objects.requireNonNull(descriptor, "descriptor");
    if (byId.containsKey(descriptor.id())) {
      throw new IllegalStateException("operation already registered: " + descriptor.id());
    }
    byId.put(descriptor.id(), descriptor);
  }

  public synchronized List<SecuredOperationDescriptor> all() {
    return List.copyOf(byId.values());
  }

  public synchronized Optional<SecuredOperationDescriptor> findById(String id) {
    return Optional.ofNullable(byId.get(id));
  }

  public synchronized boolean isEmpty() {
    return byId.isEmpty();
  }

  /** Test seam — returns the registered map snapshot. */
  public synchronized Map<String, SecuredOperationDescriptor> snapshot() {
    return Collections.unmodifiableMap(new LinkedHashMap<>(byId));
  }
}
