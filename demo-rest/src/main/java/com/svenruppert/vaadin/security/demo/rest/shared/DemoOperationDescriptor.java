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
package com.svenruppert.vaadin.security.demo.rest.shared;

import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;

/**
 * Demo operation descriptor used by the operation registry and the CLI.
 *
 * @param id                 stable operation id
 * @param label              human-readable label
 * @param description        short description
 * @param httpMethod         HTTP verb
 * @param path               path template, may contain {id}
 * @param requiredPermission required permission, or {@code null} for authenticated-only
 */
public record DemoOperationDescriptor(
    String id,
    String label,
    String description,
    String httpMethod,
    String path,
    PermissionName requiredPermission
) {
}
