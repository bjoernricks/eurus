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
import tempfile
from io import FileIO
from typing import Optional

from httpx import HTTPStatusError
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from eurus.analyzer.dpkg import Dpkg
from eurus.analyzer.release import OSRelease
from eurus.filesystem.docker import Docker, DockerArchive
from eurus.mqtt import MQTT


async def download_docker_archive(
    client: Docker, image_name: str, file: FileIO
) -> Optional[DockerArchive]:
    try:
        await client.images.inspect(image_name)
    except HTTPStatusError:
        try:
            await client.images.pull(image_name)
        except HTTPStatusError as e:
            print(e.response.json())
            raise

    with Progress() as progress:
        task_id = progress.add_task(
            f"Downloading image '{image_name}'", total=None
        )

        async for data in client.images.get(image_name):
            file.write(data)
            progress.advance(task_id)

        file.flush()

        progress.update(task_id, total=1, completed=1)

        return DockerArchive(file.name)


async def run(console: Console, error_console: Console) -> None:
    image_name = sys.argv[1] if len(sys.argv) > 1 else "ubuntu:latest"

    async with Docker() as client:
        with tempfile.NamedTemporaryFile() as f:
            console.print(
                "[green bold]Scanning Container Image "
                f"'{image_name}'[/green bold]\n"
            )
            docker_archive = await download_docker_archive(
                client, image_name, f
            )

            os_release_file = OSRelease.detect(docker_archive)
            if os_release_file:
                os_release = OSRelease.release(os_release_file)
                console.print(
                    f"Detected Operating System '{os_release.name} "
                    f"{os_release.version_id}' for image '{image_name}'."
                )
            else:
                error_console.print(
                    f"Not possible to scan image '{image_name}'. "
                    "No OS release detected."
                )
                return

            entry = Dpkg.detect(docker_archive)
            if entry:
                packages = Dpkg.get(entry)
                console.print(
                    f"Image '{image_name}' is deb based. {len(packages)} "
                    "packages installed."
                )
            else:
                error_console.print(
                    f"Could not detect installed packages for {image_name}."
                )
                return

        async with MQTT() as client:
            scan_id = await client.start_scan(
                os_release,
                [str(package) for package in packages],
            )

            table = Table(
                title=f"Scan Results for image '{image_name}'",
                show_lines=True,
                expand=True,
            )
            table.add_column("OID")
            table.add_column("Result")

            async for message in client.results(scan_id):
                table.add_row(message.oid, message.value.strip())

            console.print(table)


def main() -> None:
    console = Console()
    error_console = Console(file=sys.stderr)

    try:
        asyncio.run(run(console, error_console))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
