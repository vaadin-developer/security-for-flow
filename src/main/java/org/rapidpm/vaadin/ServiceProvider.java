package org.rapidpm.vaadin;

import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.dependencies.core.logger.Logger;

import java.util.Iterator;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.function.Function;

import static java.util.stream.StreamSupport.stream;
import static org.rapidpm.frp.model.Result.fromOptional;

public interface ServiceProvider<T>
    extends HasLogger {
  static <T> Function<Class<T>, T> loadService() {
    return (service) -> {
      Iterator<T> iterator = ServiceLoader.load(service)
                                          .iterator();
      Iterable<T>       iterable = () -> iterator;
      final Optional<T> first    = stream(iterable.spliterator(), false).findFirst();
      return fromOptional(first).ifAbsent(() -> {
        Logger.getLogger(service)
              .warning("no implementation found for interface " + service.getName());
        throw new RuntimeException("no implementation found for interface " + service.getName());
      })
                                .get();
    };
  }

  T load();
}
