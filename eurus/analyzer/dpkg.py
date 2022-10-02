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
from email.feedparser import BytesFeedParser
from io import BufferedReader
from typing import Iterable, Optional

from eurus.docker import DockerArchive, DockerImageEntry

DPKG_STATUS_FILE = "var/lib/dpkg/status"


@dataclass
class DEBPackage:
    name: str
    version: str
    architecture: str

    def __str__(self) -> str:
        return f"{self.name}-{self.version}"


class Dpkg:
    @staticmethod
    def detect(archive: DockerArchive) -> Optional[DockerImageEntry]:
        return archive.entries.get(DPKG_STATUS_FILE)

    @staticmethod
    def get(file: BufferedReader) -> Iterable[DEBPackage]:
        # the dpkg package database uses the email format defined in RFC2822
        parser = BytesFeedParser()
        packages = []
        for line in file:
            parser.feed(line)
            if not len(line.strip()):
                # empty line we have a new message/package
                entry = parser.close()
                parser = BytesFeedParser()

                package = DEBPackage(
                    name=entry["Package"],
                    version=entry["Version"],
                    architecture=entry["Architecture"],
                )
                packages.append(package)

        return packages
