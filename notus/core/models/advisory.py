# Copyright (C) 2014-2022 Greenbone Networks GmbH
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
from typing import Any, Union

from ..sanitization import (
    basic_sanitization,
    reduce_multiple_whitespaces_to_one,
    remove_trailing_spaces_and_carriage_returns,
    replace_quotation_marks,
    sanitize_cves,
)
from .qod_type import QoDType
from .severity import Severity


def sanitize_insight(insight):
    if not insight:
        return insight

    tmp = remove_trailing_spaces_and_carriage_returns(insight)
    tmp = reduce_multiple_whitespaces_to_one(tmp).strip()

    # NOTE: The replacement of quotation marks is being done
    # after filtering out any URLs.
    # Because otherwise it's impossible to differentiate
    # between an ending single quote and an apostrophe sometimes.
    # Example: "This is when I said: 'I like my friends' ".
    # -> Because "friends'" would also include a valid apostrophe,
    # it is impossible to differentiate.

    # TODO: Determine if this is really needed pylint: disable=fixme
    # Quotation marks would break parsing of the generated VT metadata
    # due to the value of script_tag(name:"insight", value:"");
    # already being put into ""
    tmp = replace_quotation_marks(tmp)

    return basic_sanitization(tmp)


def sanitize_xrefs(xrefs: list[str]) -> list[str]:
    if not xrefs:
        return []

    # Some advisories contain URLs to NVD or MITRE, which are not allowed
    return [
        xref
        for xref in xrefs
        if "nvd.nist.gov" not in xref and "cve.mitre.org" not in xref
    ]


@dataclass(frozen=True)
class Advisory:
    oid: str = None
    title: str = None
    creation_date: int = None
    last_modification: int = None
    advisory_id: str = None
    advisory_xref: str = None
    cves: list[str] = field(default_factory=list)
    summary: str = None
    insight: str = None
    affected: str = None
    impact: str = None
    xrefs: list[str] = field(default_factory=list)
    qod_type: QoDType = QoDType.DEFAULT
    severity: Severity = field(default_factory=Severity)

    @classmethod
    def from_dict(cls, advisory: dict[str, Any]) -> "Advisory":
        """Creates advisory object from given dict.
        Iterates through all fields of the advisory
        and tries to fill them into the new advisory.

        Arguments:
            advisory: The advisory dict to fill from.

        Returns:
            The filled advisory object.
        """
        advisory_id = advisory.get("advisory_id")

        obj = cls(
            oid=advisory.get("oid"),
            title=advisory.get("title"),
            creation_date=advisory.get("creation_date"),
            last_modification=advisory.get("last_modification"),
            advisory_id=(
                advisory_id.replace(" ", "") if advisory_id else advisory_id
            ),
            advisory_xref=advisory.get("advisory_xref"),
            cves=sorted(sanitize_cves(advisory.get("cves"))),
            summary=basic_sanitization(advisory.get("summary")),
            insight=sanitize_insight(advisory.get("insight")),
            affected=basic_sanitization(advisory.get("affected")),
            impact=basic_sanitization(advisory.get("impact")),
            qod_type=QoDType.from_string(advisory.get("qod_type")),
            severity=Severity.from_dict(advisory.get("severity")),
            xrefs=sanitize_xrefs(advisory.get("xrefs")),
        )
        return obj

    def to_dict(self) -> dict[str, Union[list[str], str, dict[str, str]]]:
        """Converts the advisory object into a dict.

        Returns:
            The dict containing the advisory data.
        """
        return {
            "oid": self.oid,
            "title": self.title,
            "creation_date": self.creation_date,
            "last_modification": self.last_modification,
            "advisory_id": self.advisory_id,
            "advisory_xref": self.advisory_xref,
            "cves": self.cves,
            "summary": self.summary,
            "insight": self.insight,
            "affected": self.affected,
            "impact": self.impact,
            "xrefs": self.xrefs,
            "qod_type": self.qod_type,
            "severity": self.severity.to_dict(),
        }

    def has_empty_fields(self) -> bool:
        """Check if there are empty field in this advisory object.

        Note that cves, insight, impact and xrefs is allowed to be empty.

        Returns:
            True if there is at least on empty field. Else False.
        """
        # pylint: disable=singleton-comparison
        return (
            not self.oid
            or not self.title
            or not self.creation_date
            or not self.last_modification
            or not self.advisory_id
            or not self.advisory_xref
            or not self.summary
            or not self.affected
            or not self.qod_type
            or not self.severity
        )

    def __str__(self) -> str:
        """String representation of the advisory in dict structure.

        Returns:
            The string representation.
        """
        return str(self.to_dict())

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__qualname__} oid={self.oid} {self.to_dict()}>"
        )

    def __lt__(self, other: "Advisory") -> bool:
        """Less-than comparison.
        Used when sorting a list of advisories.

        Arguments:
            other: Other advisory to compare with.

        Returns:
            True, if less than, otherwise False.
        """
        return self.oid < other.oid

    def __eq__(self, other: "Advisory") -> bool:
        """Compares two Advisory objects for equality.

        Arguments:
            other: Other advisory to compare with.

        Returns:
            True, if equal, otherwise False.
        """
        if not isinstance(other, Advisory):
            return False

        return (
            self.oid == other.oid
            and self.title == other.title
            and self.creation_date == other.creation_date
            and self.last_modification == other.last_modification
            and self.advisory_id == other.advisory_id
            and self.advisory_xref == other.advisory_xref
            and self.cves == other.cves
            and self.summary == other.summary
            and self.insight == other.insight
            and self.affected == other.affected
            and self.impact == other.impact
            and self.xrefs == other.xrefs
            and self.qod_type == other.qod_type
            and self.severity == other.severity
        )

    def __hash__(self) -> int:
        # implement hash function for storage in dict, set, etc.
        # use oid for hashing because it is the unique id of an advisory
        # different advisories must have a different oid
        return hash(self.oid)
