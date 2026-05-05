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
package com.svenruppert.vaadin.security.demo.rest;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestResponse;

/**
 * Demo REST handlers with demo-only permissions.
 */
public final class DemoDocumentHandlers {

  /**
   * Reads a document.
   *
   * @param request  request
   * @param response response
   */
  @RequiresPermission("document:read")
  public void read(RestRequest request, RestResponse response) {
    response.status(200);
    response.body("document");
  }

  /**
   * Creates a document.
   *
   * @param request  request
   * @param response response
   */
  @RequiresPermission("document:create")
  public void create(RestRequest request, RestResponse response) {
    response.status(201);
    response.body("created");
  }

  /**
   * Deletes a document.
   *
   * @param request  request
   * @param response response
   */
  @RequiresPermission("document:delete")
  public void delete(RestRequest request, RestResponse response) {
    response.status(204);
    response.body("");
  }
}
