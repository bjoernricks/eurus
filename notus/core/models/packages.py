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

from dataclasses import dataclass
from typing import Iterable

from .sorted_set import FrozenSortedSet

DEFAULT_SPECIFIER = ">="


@dataclass(frozen=True)
class Package:
    """
    A software "package"
    """

    name: str = None
    full_version: str = None
    full_name: str = None
    specifier: str = DEFAULT_SPECIFIER

    def __post_init__(self):
        if not self.specifier:
            super().__setattr__("specifier", DEFAULT_SPECIFIER)

        if not (self.name and self.full_version) and not self.full_name:
            raise ValueError(
                "Either name and full_version or full_name must be set!"
            )

        if self.specifier and self.specifier not in [">=", "<", ">", "<=", "="]:
            raise ValueError(f"{self.specifier} is not a valid specifier!")

    def to_dict(self) -> dict[str, str]:
        """Converts a Package to a Dict.

        Returns:
            The representation of the Package as a Dict.
        """
        return {
            "name": self.name,
            "full_version": self.full_version,
            "full_name": self.full_name,
            "specifier": self.specifier,
        }

    @staticmethod
    def from_dict(package: dict[str, str]) -> "Package":
        """Converts a Dict to a Package.

        Arguments:
            package: The Dict to build the Package from.

        Returns:
            A Package built from the Dict.
        """
        return Package(
            name=package.get("name"),
            full_version=package.get("full_version"),
            full_name=package.get("full_name"),
            specifier=package.get("specifier"),
        )

    def __hash__(self) -> int:
        if self.full_name:
            return hash(self.full_name)
        return hash((self.name, self.full_version))

    def __lt__(self, other) -> bool:
        if not isinstance(other, Package):
            return False

        if self.full_name and other.full_name:
            return self.full_name < other.full_name

        return self.name + self.full_version < other.name + other.full_version


@dataclass(frozen=True)
class FixedPackages:
    """Maps an advisory oid to a list of fixed packages."""

    oid: str
    packages: FrozenSortedSet[Package]

    def __post_init__(self):
        super().__setattr__("packages", FrozenSortedSet(self.packages))

    def to_dict(self) -> dict[str, list[str]]:
        """Converts FixedPackages to a Dict.

        Returns:
            The representation of FixedPackages as a Dict.
        """
        return {
            "oid": self.oid,
            "fixed_packages": [package.to_dict() for package in self.packages],
        }

    @staticmethod
    def from_dict(
        fixed_packages_dict: dict[str, Iterable[str]]
    ) -> "FixedPackages":
        """Converts a Dict to FixedPackages.

        Arguments:
            fixed_packages_dict: The Dict to build the FixedPackages from.

        Returns:
            FixedPackages built from the Dict.
        """
        return FixedPackages(
            oid=fixed_packages_dict["oid"],
            packages=FrozenSortedSet(
                [
                    Package.from_dict(package)
                    for package in fixed_packages_dict["fixed_packages"]
                ]
            ),
        )

    def __eq__(self, other) -> bool:
        if not isinstance(other, FixedPackages):
            return False

        return self.oid == other.oid and self.packages == other.packages

    def __lt__(self, other) -> bool:
        if not isinstance(other, FixedPackages):
            return False
        return self.oid < other.oid
