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

from .advisories import Advisories
from .products import Products


@dataclass(frozen=True, kw_only=True)
class VulnerabilityInformation:
    """Stores information about gathered vulnerability information.

    The gathered vulnerability information consists of the list available
    advisories and the vulnerable products and their installed software
    packages.
    """

    advisories: Advisories = field(default_factory=Advisories)
    products: Products = field(default_factory=Products)
