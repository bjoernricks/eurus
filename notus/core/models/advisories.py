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
from typing import Iterator, Optional

from .advisory import Advisory


@dataclass(frozen=True, kw_only=True)
class DistributionAdvisories:
    """Maintains a collection of advisories per distribution"""

    family: str
    distribution: str

    _advisories: dict[str, Advisory] = field(default_factory=dict)

    def add_advisory(self, advisory: Advisory) -> None:
        """Adds an advisory.

        Arguments:
            advisory: The advisory to add.
        """
        self._advisories[advisory.oid] = advisory

    def get_advisory(self, oid: str) -> Optional[Advisory]:
        """Gets an advisory.

        Arguments:
            oid: The OID of the advisory to get.

        Returns:
            The advisory or None (if not found).
        """
        return self._advisories.get(oid)

    def update(self, other: "DistributionAdvisories") -> None:
        """Updates the advisories with the advisories from other, overwriting
        existing ones.

        Arguments:
            other: The other advisories to update with.
        """
        for advisory in other:
            self._advisories[advisory.oid] = advisory

    def __iter__(self) -> Iterator[Advisory]:
        return iter(sorted(self._advisories.values(), key=lambda a: a.oid))

    def __len__(self) -> int:
        return len(self._advisories)


@dataclass(frozen=True)
class Advisories:
    """Maps distributions to advisories"""

    _advisories: dict[str, DistributionAdvisories] = field(default_factory=dict)

    def add_advisories(self, advisories: DistributionAdvisories) -> None:
        self._advisories[advisories.distribution] = advisories

    def __getitem__(self, key: str) -> DistributionAdvisories:
        return self._advisories[key]

    def __iter__(self) -> Iterator[DistributionAdvisories]:
        return iter(self._advisories.values())

    def __len__(self) -> int:
        return len(self._advisories)
