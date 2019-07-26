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
package org.rapidpm.vaadin;

import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.dependencies.core.logger.Logger;

import java.util.Iterator;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Function;

import static java.util.stream.Collectors.toSet;
import static java.util.stream.StreamSupport.stream;

public interface ServiceProvider<T>
    extends HasLogger {
  static <T> Function<Class<T>, T> loadService() {
    return (service) -> {
      Iterator<T> iterator = ServiceLoader.load(service)
                                          .iterator();
      Iterable<T> iterable = () -> iterator;
      final Set<T> set = stream(iterable.spliterator(), false).collect(toSet());
      if (set.isEmpty()) {
        Logger.getLogger(service)
              .warning("no implementation found for interface " + service.getName());
        throw new RuntimeException("no implementation found for interface " + service.getName());
      }

      if (set.size() > 1) {
        Logger.getLogger(service)
              .warning("to many implementations found for interface " + service.getName());
        throw new RuntimeException("to many implementations found for interface " + service.getName());
      }
      return set.iterator()
                .next();
    };
  }

  T load();
}
