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
package com.svenruppert.jsentinel.bootstrap;

import java.io.PrintStream;

/**
 * Prints a one-time setup banner with the actual bootstrap token to the
 * server console. Used by {@link BootstrapMode#TRANSIENT_CONSOLE}.
 * <p>
 * Output goes to the configured {@link PrintStream} (usually
 * {@code System.out}) and intentionally not to any application logger.
 */
public final class ConsoleBootstrapTokenOutput implements BootstrapTokenOutput {

  private static final String LINE = "============================================================";

  private final PrintStream out;
  private final String setupHint;

  public ConsoleBootstrapTokenOutput(PrintStream out, String setupHint) {
    this.out = out;
    this.setupHint = setupHint == null ? "" : setupHint;
  }

  public ConsoleBootstrapTokenOutput(String setupHint) {
    this(System.out, setupHint);
  }

  @Override
  public void emit(BootstrapToken token, BootstrapConfiguration configuration) {
    out.println();
    out.println(LINE);
    out.println("Initial administrator setup required.");
    out.println();
    if (!setupHint.isEmpty()) {
      out.println(setupHint);
      out.println();
    }
    out.println("Bootstrap token:");
    out.println("  " + token.value());
    out.println();
    out.println("This token is single-use and only valid while the system is uninitialized.");
    out.println(LINE);
    out.println();
  }
}
