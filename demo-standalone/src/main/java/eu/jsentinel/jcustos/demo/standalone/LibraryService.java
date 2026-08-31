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
package eu.jsentinel.jcustos.demo.standalone;

import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.authorization.annotations.RequiresRole;

import java.util.List;

/**
 * Demo service interface guarded by the framework's annotations. Wrap
 * implementations with {@code SecuredProxy.wrap(LibraryService.class, ...)};
 * every call then runs the annotation's evaluator before delegating to
 * the implementation.
 */
public interface LibraryService {

  @RequiresPermission("book:list")
  List<String> listBooks();

  @RequiresPermission("book:borrow")
  void borrowBook(String title);

  @RequiresPermission("book:return")
  void returnBook(String title);

  @RequiresPermission("book:add")
  void addBook(String title);

  @RequiresRole("ADMIN")
  void removeBook(String title);
}
