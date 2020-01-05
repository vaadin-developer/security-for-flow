/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package junit.demo;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.openqa.selenium.chrome.ChromeOptions;
import org.testcontainers.containers.BrowserWebDriverContainer;
import org.testcontainers.containers.DefaultRecordingFileFactory;
import org.testcontainers.lifecycle.TestDescription;

import java.io.File;
import java.util.Optional;

import static org.junit.jupiter.api.extension.ExtensionContext.Namespace.GLOBAL;
import static org.testcontainers.containers.BrowserWebDriverContainer.VncRecordingMode.RECORD_ALL;

public class WebdriverExtension implements BeforeEachCallback, AfterEachCallback {

  @Override
  public void beforeEach(ExtensionContext extensionContext) throws Exception {

    final BrowserWebDriverContainer container = new BrowserWebDriverContainer()
        .withCapabilities(new ChromeOptions())
        .withRecordingMode(RECORD_ALL , new File("./target/"))
//        .withRecordingMode(SKIP , new File("./target/"))
        .withRecordingFileFactory(new DefaultRecordingFileFactory());

    container.start();
    extensionContext
        .getStore(GLOBAL)
        .put(BrowserWebDriverContainer.class.getSimpleName() , container);

  }

  @Override
  public void afterEach(ExtensionContext extensionContext) throws Exception {

    final BrowserWebDriverContainer container = extensionContext
        .getStore(GLOBAL)
        .get(BrowserWebDriverContainer.class.getSimpleName() , BrowserWebDriverContainer.class);

    final String uniqueId = extensionContext.getUniqueId();
    final String name = extensionContext.getRequiredTestMethod().getName();


    container.afterTest(new TestDescription() {
      @Override
      public String getTestId() { return uniqueId; }

      @Override
      public String getFilesystemFriendlyName() { return name; }
    } , Optional.empty());

    container
        .stop();
  }
}
