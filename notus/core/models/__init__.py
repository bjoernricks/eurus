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

from .advisories import Advisories, DistributionAdvisories
from .advisory import Advisory
from .information import VulnerabilityInformation
from .packages import FixedPackages, Package
from .product import Product, ProductPackages
from .products import Products
from .severity import Severity

__all__ = (
    "Advisories",
    "Advisory",
    "DistributionAdvisories",
    "FixedPackages",
    "Package",
    "Product",
    "ProductPackages",
    "Products",
    "Severity",
    "VulnerabilityInformation",
)
