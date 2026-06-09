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
package com.svenruppert.jsentinel.demo.standalone;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class InMemoryLibraryService implements LibraryService {

  private final Set<String> books = new HashSet<>(Set.of(
      "Effective Java", "Clean Code", "The Pragmatic Programmer"));
  private final Set<String> borrowed = new HashSet<>();

  @Override
  public List<String> listBooks() {
    List<String> sorted = new ArrayList<>(books);
    sorted.sort(String::compareTo);
    return List.copyOf(sorted);
  }

  @Override
  public void borrowBook(String title) {
    if (!books.contains(title)) {
      throw new IllegalArgumentException("Unknown book: " + title);
    }
    if (!borrowed.add(title)) {
      throw new IllegalStateException("Already borrowed: " + title);
    }
  }

  @Override
  public void returnBook(String title) {
    if (!borrowed.remove(title)) {
      throw new IllegalStateException("Not currently borrowed: " + title);
    }
  }

  @Override
  public void addBook(String title) {
    if (!books.add(title)) {
      throw new IllegalStateException("Already in stock: " + title);
    }
  }

  @Override
  public void removeBook(String title) {
    if (!books.remove(title)) {
      throw new IllegalStateException("Unknown book: " + title);
    }
    borrowed.remove(title);
  }
}
