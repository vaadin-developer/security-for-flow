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
