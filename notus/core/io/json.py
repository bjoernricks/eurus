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
import json
import logging
from pathlib import Path
from typing import Any, Iterator, Optional, Union

from ..errors import AdvisoriesIOError, ProductsIOError
from ..models import (
    Advisories,
    Advisory,
    OperatingSystemAdvisories,
    Package,
    Product,
    Products,
)
from .advisories import AdvisoriesIO
from .products import ProductsIO


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        try:
            return super().default(o)
        except TypeError:
            return o.__dict__


VERSION = "1.0"

_DEFAULT_INDENTATION = 4

logger = logging.getLogger(__name__)


def _operating_system_file_path(path: Path, distribution: str) -> Path:
    file = path / distribution.lower()
    return file.with_suffix(file.suffix + ".notus")


class JSONOperatingSystemAdvisories:
    def __init__(
        self,
        *,
        indent: Optional[int] = _DEFAULT_INDENTATION,
    ) -> None:
        self._indent = indent

    def read(self, notus_file: Path) -> OperatingSystemAdvisories:
        with notus_file.open("r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise AdvisoriesIOError(
                    f"Could not read '{notus_file.absolute()}'. "
                    f"Error was {e}"
                ) from None

        operating_system = notus_file.stem

        version = data.get("version")
        if not version:
            raise AdvisoriesIOError("No version information found")

        family = data.get("family")
        if not family:
            raise AdvisoriesIOError("No family information found")

        if version != VERSION:
            raise AdvisoriesIOError(
                f"Unknown version {version}. "
                f"Only version {VERSION} is supported."
            )

        os_advisories = OperatingSystemAdvisories(
            operating_system=operating_system, family=family
        )
        for raw_advisory in data["advisories"]:
            advisory = Advisory.from_dict(raw_advisory)
            os_advisories.add_advisory(advisory)

        return os_advisories

    def write(
        self, advisories: OperatingSystemAdvisories, notus_file: Path
    ) -> None:
        data = {
            "version": VERSION,
            "family": advisories.family,
        }
        data["advisories"] = []

        for advisory in advisories:
            advisory_data = advisory.to_dict()
            data["advisories"].append(advisory_data)

        with notus_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=self._indent, cls=CustomJSONEncoder)


class JSONAdvisories(AdvisoriesIO):
    def __init__(
        self,
        advisories_directory: Union[str, Path],
        *,
        pattern: str = "",
        indent: Optional[int] = _DEFAULT_INDENTATION,
    ):
        self._advisories_directory = (
            Path(advisories_directory)
            if isinstance(advisories_directory, str)
            else advisories_directory
        )
        self._indent = indent
        self._pattern = pattern

    def read(self) -> Advisories:
        """Reads advisories.

        Raises:
            AdvisoriesIOError: When there's an error while reading.

        Returns:
            The advisories read.
        """
        if not self._advisories_directory.exists():
            raise AdvisoriesIOError(
                f"Advisories directory {self._advisories_directory} does not "
                "exist."
            )

        advisories = Advisories()

        os_reader = JSONOperatingSystemAdvisories(indent=self._indent)

        for file_path in self._advisories_directory.iterdir():
            if (
                not file_path.is_file()
                or not file_path.suffix == ".notus"
                or (self._pattern and not file_path.match(self._pattern))
            ):
                continue

            os_advisories = os_reader.read(file_path)
            advisories.add_advisories(os_advisories)

        return advisories

    def write(self, advisories: Advisories) -> None:
        """Writes advisories.

        Arguments:
            advisories: The advisories to write.
        """
        self._advisories_directory.mkdir(parents=True, exist_ok=True)

        os_writer = JSONOperatingSystemAdvisories(indent=self._indent)

        for os_advisories in advisories:
            notus_file = _operating_system_file_path(
                self._advisories_directory, os_advisories.operating_system
            )
            os_writer.write(os_advisories, notus_file)


def _product_file_path(path: Path, product: str) -> Path:
    """Builds the file path for a product to save to.

    Arguments:
        path: The base path.
        product: The product name.

    Returns:
        The file path.
    """
    file = path / product.lower().replace(" ", "_")
    return file.with_suffix(file.suffix + ".notus")


class JSONProducts(ProductsIO):
    def __init__(
        self,
        products_directory: Optional[Union[str, Path]],
        *,
        pattern: str = "",
        indent: Optional[int] = _DEFAULT_INDENTATION,
    ):
        self._products_directory = (
            Path(products_directory)
            if isinstance(products_directory, str)
            else products_directory
        )
        self._indent = indent
        self._pattern = pattern

    def read(self) -> Products:
        """Reads products.

        Raises:
            ProductsIOError if an error occurs during reading the products

        Returns:
            The products read.
        """
        products = Products()

        if not self._products_directory.exists():
            raise ProductsIOError(
                f"Products directory '{self._products_directory}' does not "
                "exist."
            )

        for _, data in self._read_files_contents():
            product = Product(
                name=data["product_name"], package_type=data["package_type"]
            )
            products.add_product(product)

            for advisory in data["advisories"]:
                product.add_packages(
                    advisory["oid"],
                    [
                        Package.from_dict(package)
                        for package in advisory["fixed_packages"]
                    ],
                )

        return products

    def write(self, products: Products) -> None:
        """Writes products.

        Arguments:
            package_type: The type of the packages (e.g. "rpm").
            products: The products to write.
        """
        self._products_directory.mkdir(parents=True, exist_ok=True)

        for product in products:
            data = {
                "version": VERSION,
                "package_type": product.package_type,
                "product_name": product.name,
            }
            advisories = []
            data["advisories"] = advisories
            for package in product.packages:
                advisories.append(package.to_dict())

            product_file = _product_file_path(
                self._products_directory, product.name
            )

            with product_file.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=self._indent, cls=CustomJSONEncoder)

    def _read_files_contents(self) -> Iterator[tuple[Path, dict[str, Any]]]:
        """Generator for the filename and parsed JSON content of product files.

        Yields:
            The file path and parsed content of the file.
        """
        for file_path in self._products_directory.iterdir():
            if (
                not file_path.is_file()
                or not file_path.suffix == ".notus"
                or (self._pattern and not file_path.match(self._pattern))
            ):
                continue

            with file_path.open("r", encoding="utf-8") as f:
                try:
                    yield file_path, json.load(f)
                except json.JSONDecodeError as e:
                    raise ProductsIOError(
                        f"Could not read '{file_path.absolute()}'. "
                        f"Error was {e}"
                    ) from None
