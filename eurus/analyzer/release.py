# Copyright (C) 2022 Greenbone Networks GmbH
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
from io import BufferedReader
from typing import Optional

from eurus.docker import DockerArchive, DockerImageEntry

ETC_OS_RELEASE = "etc/os-release"
USR_LIB_OS_RELEASE = "usr/lib/os-release"


@dataclass
class OSReleaseInfo:
    name: Optional[str]
    id: Optional[str]
    version_id: Optional[str]
    pretty_name: Optional[str]
    cpe_id: Optional[str]


def cleanup(item: str) -> str:
    """
    Values in os-release can use double or single quotes
    """
    item = item.strip()
    if item.startswith('"'):
        item = item.strip('"')
    elif item.startswith("'"):
        item = item.strip("'")
    return item


class OSRelease:
    @staticmethod
    def detect(archive: DockerArchive) -> Optional[DockerImageEntry]:
        os_release_entry = archive.entries.get(ETC_OS_RELEASE)
        if os_release_entry:
            return os_release_entry

        os_release_entry = archive.entries.get(USR_LIB_OS_RELEASE)
        return os_release_entry

    @staticmethod
    def release(file: BufferedReader) -> OSReleaseInfo:
        name = None
        version_id = None
        pretty_name = None
        cpe_id = None
        dist_id = None

        for line in file:
            line = line.decode("utf8", errors="replace")
            if line.startswith("PRETTY_NAME="):
                pretty_name = cleanup(line[12:])
            elif line.startswith("VERSION_ID="):
                version_id = cleanup(line[11:])
            elif line.startswith("NAME="):
                name = cleanup(line[5:])
            elif line.startswith("CPE_NAME="):
                cpe_id = cleanup(line[8:])
            elif line.startswith("ID="):
                dist_id = cleanup(line[3:])

        return OSReleaseInfo(
            name=name,
            version_id=version_id,
            pretty_name=pretty_name,
            cpe_id=cpe_id,
            id=dist_id,
        )
