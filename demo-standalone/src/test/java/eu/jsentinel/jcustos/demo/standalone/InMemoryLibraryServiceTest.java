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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("InMemoryLibraryService — non-secured contract")
class InMemoryLibraryServiceTest {

  @Test
  @DisplayName("listBooks returns the catalog sorted alphabetically")
  void listBooksIsSorted() {
    InMemoryLibraryService svc = new InMemoryLibraryService();
    svc.addBook("Zzz");
    svc.addBook("Aaa");

    List<String> books = svc.listBooks();
    List<String> expectedSorted = books.stream().sorted().toList();
    assertEquals(expectedSorted, books,
        "listBooks must return its result alphabetically sorted; got: " + books);

    // explicit element checks pin the ordering
    int aaaIdx = books.indexOf("Aaa");
    int zzzIdx = books.indexOf("Zzz");
    org.junit.jupiter.api.Assertions.assertTrue(aaaIdx < zzzIdx,
        "Aaa must come before Zzz in the sorted list: " + books);
  }
}
