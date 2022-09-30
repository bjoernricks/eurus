# Copyright (C) 2021-2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from dataclasses import dataclass, field
from typing import Iterable

from .packages import FixedPackages, Package
from .sorted_set import SortedSet


@dataclass(frozen=True)
class ProductPackages:
    """A set of fixed packages lists for a product."""

    _fixed_packages: SortedSet[FixedPackages] = field(
        default_factory=lambda: SortedSet(index_key=lambda p: p.oid)
    )

    def remove(self, oid: str):
        self._fixed_packages.remove_for_index(oid)

    def add_packages(self, package: FixedPackages) -> None:
        """Add packages.

        Arguments:
            package: The packages to add.
        """
        self._fixed_packages.add(package)

    def __iter__(self) -> Iterable[FixedPackages]:
        return iter(self._fixed_packages)

    def __len__(self):
        return len(self._fixed_packages)


@dataclass(frozen=True)
class Product:
    name: str
    package_type: str
    packages: ProductPackages = field(default_factory=ProductPackages)

    def _add_fixed_packages(self, fixed_packages: FixedPackages) -> None:
        self.packages.add_packages(fixed_packages)

    def add_packages(self, oid: str, packages: Iterable[Package]) -> None:
        """Add packages to a product with OID.

        Arguments:
            oid: The OID to add to.
            packages: The Packages to add.
        """
        self._add_fixed_packages(FixedPackages(oid, set(packages)))
