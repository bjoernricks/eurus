# -*- coding: utf-8 -*-
# Copyright (C) 2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from collections.abc import Sequence
from typing import Callable, Generic, Hashable, Iterable, TypeVar

from sortedcontainers import SortedSet as _SortedSet

T = TypeVar("T", bound=Hashable)  # pylint: disable=invalid-name


class FrozenSortedSet(Sequence, Generic[T]):
    """The three properties of a FrozenSortedSet are
    that elements are unique (by their hash / index_key),
    that the elements are sorted (by their lt method / sort_key),
    and that it's frozen (immutable)."""

    _elements: _SortedSet
    _index_keys: set

    def __init__(
        self,
        elements: Iterable[T],
        sort_key: Callable = None,
        index_key: Callable = None,
    ):
        """Initializes a new FrozenSortedSet.

        Arguments:
            elements: The elements to build from.
            sort_key: The key for sorting the elements.
                Defaults to None (the elements lt method will be used).
            index_key: The key for indexing the elements.
                Defaults to None (the elements hash method will be used).
        """
        self._elements = _SortedSet(elements, sort_key)

        if index_key:
            # Create a list of index keys, e.g. OIDs
            self._index_keys = set(
                [index_key(element) for element in self._elements]
            )
            if len(self._elements) != len(self._index_keys):
                tmp = self._index_keys.copy()
                # Iterate over all elements and remove any duplicates
                for element in self._elements[:]:
                    try:
                        tmp.remove(index_key(element))
                    except KeyError:
                        self._elements.remove(element)

    def __len__(self) -> int:
        return len(self._elements)

    def __getitem__(self, index) -> T:
        return self._elements[index]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FrozenSortedSet):
            return self._elements == other._elements
        elif isinstance(other, Sequence):
            return list(self._elements) == other
        return False

    def __hash__(self) -> int:
        return hash(tuple(self._elements))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(list(self._elements))})"


class SortedSet(FrozenSortedSet, Generic[T]):
    """The SortedSet inherits from FrozenSortedSet and offers the same
    functionality, except for the immutability: A SortedSet is mutable.
    """

    _index_key: Callable

    def __init__(
        self,
        elements: Iterable[T] = None,
        sort_key: Callable = None,
        index_key: Callable = None,
    ):
        """Initializes a new SortedSet.

        Arguments:
            elements: The elements to build from.
            sort_key: The key for sorting the elements.
                Defaults to None (the elements lt method will be used).
            index_key: The key for indexing the elements.
                Defaults to None (the elements hash method will be used).
        """
        super().__init__(elements if elements else [], sort_key, index_key)
        self._index_key = index_key

    def __delitem__(self, index: int):
        element = self._elements[index]
        del self._elements[index]
        if self._index_key:
            self._index_keys.remove(self._index_key(element))

    def add(self, value: T) -> None:
        """Adds a value to the SortedSet.

        Arguments:
            value: The value to add.
        """
        if self._index_key:
            index_key = self._index_key(value)
            if index_key in self._index_keys:
                # element already is in elements, remove it
                # This loop is only a workaround due to its runtime performance
                for element in self._elements:
                    if self._index_key(element) == index_key:
                        self._elements.remove(element)
                        break
            self._index_keys.add(index_key)
        self._elements.add(value)

    def remove(self, value: T) -> None:
        """Removes a value from the SortedSet.

        Arguments:
            value: The value to remove.
        """
        self._elements.remove(value)
        if self._index_key:
            self._index_keys.remove(self._index_key(value))

    def remove_for_index(self, index_key: str):
        """Removes objects based on the index key

        Arguments:
            index_key: Index key of the item to be deleted

        Raises:
            IndexError: When no index key is set.
        """
        if not self._index_key:
            raise IndexError("No index is set.")

        if index_key not in self._index_keys:
            return

        for element in self._elements:
            if self._index_key(element) == index_key:
                self.remove(element)

    def __hash__(self) -> int:
        raise TypeError(f"unhashable type: {type(self).__name__}")
