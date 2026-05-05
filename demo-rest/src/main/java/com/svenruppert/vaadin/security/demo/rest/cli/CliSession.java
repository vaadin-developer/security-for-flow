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
package com.svenruppert.vaadin.security.demo.rest.cli;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-memory CLI session holding the demo bearer token and the last
 * server-provided operation list.
 */
public final class CliSession {

  private String token;
  private String displayName;
  private final Map<String, OperationEntry> operations = new LinkedHashMap<>();

  public boolean isLoggedIn() {
    return token != null;
  }

  public String token() {
    return token;
  }

  public String displayName() {
    return displayName;
  }

  public void setLogin(String token, String displayName) {
    this.token = token;
    this.displayName = displayName;
  }

  public void clear() {
    this.token = null;
    this.displayName = null;
    this.operations.clear();
  }

  public void rememberOperation(String id, String label, String method, String path) {
    operations.put(id, new OperationEntry(id, label, method, path));
  }

  public void clearOperations() {
    operations.clear();
  }

  public OperationEntry operation(String id) {
    return operations.get(id);
  }

  public Map<String, OperationEntry> operations() {
    return operations;
  }

  public record OperationEntry(String id, String label, String method, String path) {
  }
}
