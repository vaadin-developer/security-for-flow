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

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.openqa.selenium.WebDriver;
import org.rapidpm.frp.Transformations;
import org.rapidpm.frp.functions.CheckedPredicate;
import org.rapidpm.frp.functions.CheckedSupplier;
import org.testcontainers.containers.BrowserWebDriverContainer;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;
import java.util.function.Supplier;

import static org.junit.jupiter.api.extension.ExtensionContext.Namespace.GLOBAL;
import static org.rapidpm.frp.StringFunctions.notEmpty;
import static org.rapidpm.frp.StringFunctions.notStartsWith;
import static org.rapidpm.frp.Transformations.not;

public class WebDriverParameterResolver implements ParameterResolver {

  @Override
  public boolean supportsParameter(ParameterContext parameterContext ,
                                   ExtensionContext extensionContext)
      throws ParameterResolutionException {
    final Class<?> type = parameterContext.getParameter().getType();
    return WebDriverInfo.class.isAssignableFrom(type);
  }

  @Override
  public Object resolveParameter(ParameterContext parameterContext ,
                                 ExtensionContext extensionContext)
      throws ParameterResolutionException {

    final BrowserWebDriverContainer container = extensionContext
        .getStore(GLOBAL)
        .get(BrowserWebDriverContainer.class.getSimpleName() , BrowserWebDriverContainer.class);


    final String property = System.getProperty("os.name");
    final boolean osx = property.contains("Mac OS X");

    return new WebDriverInfo(container.getWebDriver() ,
                             (osx) ? "host.docker.internal" : localeIP().get(),
                             container.getVncAddress());
  }

  public static class WebDriverInfo {
    private WebDriver webdriver;
    private String hostIpAddress;
    private String vncAdress;

    public WebDriverInfo(WebDriver webdriver , String hostIpAddress , String vncAdress) {
      this.webdriver = webdriver;
      this.hostIpAddress = hostIpAddress;
      this.vncAdress = vncAdress;
    }

    public WebDriver getWebdriver() {
      return webdriver;
    }

    public String getHostIpAddress() {
      return hostIpAddress;
    }

    public String getVncAdress() {
      return vncAdress;
    }
  }

  public static Supplier<String> localeIP() {
    return () -> {
      final CheckedSupplier<Enumeration<NetworkInterface>> checkedSupplier =
          NetworkInterface::getNetworkInterfaces;

      return Transformations.<NetworkInterface>enumToStream()
          .apply(checkedSupplier.getOrElse(Collections::emptyEnumeration))
          .filter((CheckedPredicate<NetworkInterface>) NetworkInterface::isUp)
          .map(NetworkInterface::getInetAddresses)
          .flatMap(iaEnum -> Transformations.<InetAddress>enumToStream().apply(iaEnum))
          .filter(inetAddress -> inetAddress instanceof Inet4Address)
          .filter(not(InetAddress::isMulticastAddress)).filter(not(InetAddress::isLoopbackAddress))
          .map(InetAddress::getHostAddress).filter(notEmpty())
          .filter(adr -> notStartsWith().apply(adr, "127"))
          .filter(adr -> notStartsWith().apply(adr, "169.254"))
          .filter(adr -> notStartsWith().apply(adr, "255.255.255.255"))
          .filter(adr -> notStartsWith().apply(adr, "255.255.255.255"))
          .filter(adr -> notStartsWith().apply(adr, "0.0.0.0"))
          // .filter(adr -> range(224, 240).noneMatch(nr -> adr.startsWith(valueOf(nr))))
          .findFirst().orElse("localhost");
    };
  }
}
