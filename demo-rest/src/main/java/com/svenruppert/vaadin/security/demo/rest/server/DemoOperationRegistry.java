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

import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoPermission;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoOperationDescriptor;

import java.util.List;

/**
 * Demo operation registry. Lists callable demo operations and filters them
 * server-side based on the current subject's permissions.
 */
public final class DemoOperationRegistry {

  private final List<DemoOperationDescriptor> operations = List.of(
      new DemoOperationDescriptor(
          "list-documents",
          "List documents",
          "List all documents",
          "GET",
          "/api/documents",
          DemoPermission.DOCUMENT_READ.permissionName()),
      new DemoOperationDescriptor(
          "create-document",
          "Create document",
          "Create a document with the given title",
          "POST",
          "/api/documents",
          DemoPermission.DOCUMENT_CREATE.permissionName()),
      new DemoOperationDescriptor(
          "delete-document",
          "Delete document",
          "Delete the document with the given id",
          "DELETE",
          "/api/documents/{id}",
          DemoPermission.DOCUMENT_DELETE.permissionName()),
      new DemoOperationDescriptor(
          "admin-status",
          "Admin status",
          "Read the admin status endpoint",
          "GET",
          "/api/admin/status",
          DemoPermission.ADMIN_ACCESS.permissionName()));

  public List<DemoOperationDescriptor> all() {
    return operations;
  }

  public List<DemoOperationDescriptor> visibleFor(SecuritySubject subject) {
    return operations.stream()
        .filter(op -> isAllowed(subject, op.requiredPermission()))
        .toList();
  }

  private static boolean isAllowed(SecuritySubject subject, PermissionName required) {
    if (required == null) return true;
    return subject.permissions().contains(required);
  }
}
