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
from contextlib import AsyncExitStack
from pathlib import Path
from typing import AsyncGenerator
from uuid import uuid4

import paho.mqtt.client as mqtt
from asyncio_mqtt import Client, ProtocolVersion

from eurus.analyzer.dpkg import Dpkg
from eurus.analyzer.release import OSRelease, OSReleaseInfo
from eurus.docker import Docker, DockerArchive
from notus.core.messages.result import ResultMessage
from notus.core.messages.start import ScanStartMessage
from notus.core.messages.status import ScanStatus, ScanStatusMessage


def get_notus_operating_system(os_release: OSReleaseInfo) -> str:
    return f"{os_release.id} {os_release.version_id}"


def main() -> None:
    asyncio.run(run())


async def handle_result_messages(
    messages: AsyncGenerator[mqtt.MQTTMessage, None]
):
    async for message in messages:
        result_message = ResultMessage.load(message.payload)
        print(
            f"Result for Scan with ID '{result_message.scan_id}' Type "
            f"'{result_message.result_type}' OID '{result_message.oid}' "
            f"value '{result_message.value}'"
        )


async def handle_scan_status_messages(
    messages: AsyncGenerator[mqtt.MQTTMessage, None]
):
    async for message in messages:
        scan_status_message = ScanStatusMessage.load(message.payload)
        print(
            f"Status of Scan with ID '{scan_status_message.scan_id}' changed "
            f"to '{scan_status_message.status}'"
        )
        if scan_status_message.status == ScanStatus.FINISHED:
            raise ValueError("Scan Finished")


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
                os_release = OSRelease.release(entry.extract())
                print(f"Found {os_release}")
            else:
                print("No OS Release detected")
                return

            entry = Dpkg.detect(docker_archive)
            if entry:
                packages = Dpkg.get(entry.extract())
                print(f"Is deb based. {len(packages)} packages installed.")
            else:
                print("It is not deb based")
                return

            scan_id = str(uuid4())
            message = ScanStartMessage(
                scan_id=scan_id,
                host_ip="",
                host_name="",
                os_release=get_notus_operating_system(os_release),
                package_list=[str(package) for package in packages],
            )
            async with AsyncExitStack() as stack:
                client = Client(
                    "localhost",
                    client_id="eurus.client",
                    protocol=ProtocolVersion.V5,
                )
                await stack.enter_async_context(client)
                await client.subscribe(ResultMessage.topic)
                await client.subscribe(ScanStatusMessage.topic)

                print(f"Starting scan with ID '{scan_id}'")

                await client.publish(message.topic, message.dump(), qos=1)
                manager = client.filtered_messages(
                    ResultMessage.topic, queue_maxsize=1
                )
                messages = await stack.enter_async_context(manager)
                result_task = asyncio.create_task(
                    handle_result_messages(messages)
                )

                manager = client.filtered_messages(
                    ScanStatusMessage.topic, queue_maxsize=1
                )
                messages = await stack.enter_async_context(manager)
                scan_status_task = asyncio.create_task(
                    handle_scan_status_messages(messages)
                )

                try:
                    await asyncio.gather(scan_status_task, result_task)
                except ValueError:
                    return

    return


if __name__ == "__main__":
    main()
