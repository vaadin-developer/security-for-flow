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
package com.svenruppert.jsentinel.demo.rest.cli;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * CLI entry point for the demo REST client.
 * <p>
 * Usage: {@code java ...DemoRestCli [base-url]}
 * <p>
 * The default base URL is {@code http://localhost:8080}.
 */
public final class DemoRestCli {

  private DemoRestCli() {
  }

  public static void main(String[] args) throws IOException {
    String baseUrl = args.length > 0 ? args[0] : "http://localhost:8080";
    CliOperationClient client = new CliOperationClient(baseUrl);
    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    new CliCommandLoop(reader, System.out, client).run();
  }
}
