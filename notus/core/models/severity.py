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


@dataclass
class Severity:
    origin: str = None
    date: int = None
    cvss_v2: str = None
    cvss_v3: str = None

    @classmethod
    def from_dict(cls, severity: dict[str, str] = None) -> "Severity":
        """Converts a Dict to a Severity.

        Arguments:
            severity: The Dict to build the Severity from.

        Returns:
            Severity built from the Dict.
        """
        if not severity:
            severity = {}

        return cls(
            origin=severity.get("origin"),
            date=severity.get("date"),
            cvss_v2=severity.get("cvss_v2"),
            cvss_v3=severity.get("cvss_v3"),
        )

    def to_dict(self) -> dict[str, str]:
        """Converts a Severity to a Dict.

        Returns:
            The representation of a Severity as a Dict.
        """
        return {
            "origin": self.origin,
            "date": self.date,
            "cvss_v2": self.cvss_v2,
            "cvss_v3": self.cvss_v3,
        }

    def has_empty_fields(self) -> bool:
        """Checks if there are empty field in this object.

        Returns:
            True if there is at least one empty field. Else False.
        """
        return (
            not self.origin
            or not self.date
            or not self.cvss_v2
            or not self.cvss_v3
        )

    def has_empty_cvssv2_field(self) -> bool:
        """Checks if cvss_v2 field is empty in this object.

        Returns:
            True if cvss_v2 field is empty. Else False.
        """
        return not self.cvss_v2

    @staticmethod
    def get_defaults() -> tuple[str, int, str, str]:
        """Gets the severity defaults.

        Returns:
            Tuple of (origin, time, cvss_v2, cvss_v3).
        """
        return (
            "Greenbone",
            None,
            "AV:N/AC:L/Au:N/C:P/I:N/A:N",
        )

    def has_default_cvssv2(self) -> bool:
        """Checks if the advisories CVSSv2 information equals
        the default value.

        Returns:
            True if equal, otherwise False.
        """
        return self.cvss_v2 == self.get_defaults()[2]

    def set_defaults(self) -> None:
        """Sets the severity defaults."""

        self.cvss_v3 = None
        (
            self.origin,
            self.date,
            self.cvss_v2,
        ) = self.get_defaults()
