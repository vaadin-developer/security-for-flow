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
package com.svenruppert.vaadin.security.bootstrap;

import java.io.PrintStream;
import java.nio.file.Path;

/**
 * Tells the operator that the token has been written to a file. Logs only
 * the path — the actual token value is never echoed.
 */
public final class FileBootstrapTokenOutput implements BootstrapTokenOutput {

  private static final String LINE = "============================================================";

  private final PrintStream out;

  public FileBootstrapTokenOutput(PrintStream out) {
    this.out = out;
  }

  public FileBootstrapTokenOutput() {
    this(System.out);
  }

  @Override
  public void emit(BootstrapToken token, BootstrapConfiguration configuration) {
    Path path = configuration.tokenFilePath();
    out.println();
    out.println(LINE);
    out.println("Initial administrator setup required.");
    out.println("Bootstrap token file:");
    out.println("  " + (path == null ? "(unknown)" : path.toAbsolutePath()));
    out.println();
    out.println("Use the value in the file to complete the initial admin setup.");
    out.println(LINE);
    out.println();
  }
}
