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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.api.operations.OperationVisibilityService;
import com.svenruppert.vaadin.security.authorization.api.operations.SecuredOperationDescriptor;
import com.svenruppert.vaadin.security.authorization.api.operations.SecuredOperationRegistry;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoPermission;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Thin demo wrapper around the generic
 * {@link SecuredOperationRegistry} + {@link OperationVisibilityService}.
 * <p>
 * REST metadata (HTTP method, URL path) is stored in the descriptor's
 * {@code attributes} so the registry stays adapter-neutral.
 */
public final class DemoOperationRegistry {

  /** Attribute keys for REST descriptors. */
  public static final String ATTR_HTTP_METHOD = "httpMethod";
  public static final String ATTR_HTTP_PATH = "path";

  private final SecuredOperationRegistry registry = new SecuredOperationRegistry();
  private final OperationVisibilityService visibility;

  public DemoOperationRegistry() {
    register("list-documents", "List documents", "List all documents",
        "GET", "/api/documents", DemoPermission.DOCUMENT_READ);
    register("create-document", "Create document", "Create a document with the given title",
        "POST", "/api/documents", DemoPermission.DOCUMENT_CREATE);
    register("delete-document", "Delete document", "Delete the document with the given id",
        "DELETE", "/api/documents/{id}", DemoPermission.DOCUMENT_DELETE);
    register("admin-status", "Admin status", "Read the admin status endpoint",
        "GET", "/api/admin/status", DemoPermission.ADMIN_ACCESS);
    this.visibility = new OperationVisibilityService(registry);
  }

  private void register(String id, String label, String description,
      String httpMethod, String path, DemoPermission requiredPermission) {
    registry.register(new SecuredOperationDescriptor(
        id, label, description,
        "rest-endpoint", path, httpMethod.toLowerCase(),
        Set.of(),
        Set.of(requiredPermission.permissionName()),
        Map.of(ATTR_HTTP_METHOD, httpMethod, ATTR_HTTP_PATH, path)));
  }

  public List<SecuredOperationDescriptor> all() {
    return registry.all();
  }

  public List<SecuredOperationDescriptor> visibleFor(JSentinelSubject subject) {
    return visibility.visibleFor(subject);
  }
}
