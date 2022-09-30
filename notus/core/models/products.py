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
from typing import Iterator

from .product import Product


@dataclass(frozen=True)
class Products:
    """Maps products to fixed packages."""

    _products: dict[str, Product] = field(default_factory=dict)

    def add_product(self, product: Product):
        self._products[product.name] = product

    def __getitem__(self, key: str) -> Product:
        return self._products[key]

    def __iter__(self) -> Iterator[Product]:
        return iter(
            sorted(self._products.values(), key=lambda product: product.name)
        )

    def __len__(self) -> int:
        return len(self._products)
