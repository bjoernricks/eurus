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

import asyncio
import sys
from pathlib import Path

from eurus.analyzer.dpkg import Dpkg
from eurus.analyzer.release import OSRelease
from eurus.docker import Docker, DockerArchive


def main() -> None:
    asyncio.run(run())


async def run() -> None:
    image_name = (
        sys.argv[1] if len(sys.argv) > 1 else "greenbone/gvm-tools:latest"
    )
    destination = sys.argv[2] if len(sys.argv) > 2 else "/tmp/image.tar.gz"

    async with Docker() as client:
        # response = await client.images.list()

        # for image in response:
        #     print(image["Id"], image["RepoTags"])

        # async with aiofiles.tempfile.NamedTemporaryFile("wb") as f:
        with Path(destination).open("wb") as f:
            print(f"Downloading {image_name} to {destination}")

            async for data in client.images.get(image_name):
                f.write(data)

            f.flush()

            docker_archive = DockerArchive(f.name)

            print(docker_archive.tags)

            for layer in docker_archive.layers:
                print(str(layer))

            # for entry in docker_archive.entries:
            #     print(entry)

            # status_file_entry = docker_archive.entries.get(DPKG_STATUS_FILE)
            # status_file = status_file_entry.extract()
            # for line in status_file.readlines():
            #     print(line.decode("utf8", errors="replace"), end="")

            entry = OSRelease.detect(docker_archive)
            if entry:
                print(OSRelease.release(entry.extract()))
            else:
                print("No OS Release detected")

            entry = Dpkg.detect(docker_archive)
            if entry:
                packages = Dpkg.get(entry.extract())
                print(f"Is deb based. {len(packages)} packages installed.")
                for package in packages:
                    print(package)
            else:
                print("It is not deb based")

    return


if __name__ == "__main__":
    main()
