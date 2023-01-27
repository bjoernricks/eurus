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
from asyncio import Event, Queue
from types import TracebackType
from typing import AsyncContextManager, AsyncGenerator
from uuid import uuid4

import paho.mqtt.client as mqtt
from asyncio_mqtt import Client, ProtocolVersion

from eurus.analyzer.release import OSReleaseInfo
from notus.core.messages.result import ResultMessage
from notus.core.messages.start import ScanStartMessage
from notus.core.messages.status import ScanStatus, ScanStatusMessage


def create_scan_id() -> str:
    return str(uuid4())


def get_notus_operating_system(os_release: OSReleaseInfo) -> str:
    return f"{os_release.id} {os_release.version_id}"


class MQTT(AsyncContextManager):
    def __init__(self) -> None:
        self._client = Client(
            "localhost",
            client_id="eurus.client",
            protocol=ProtocolVersion.V5,
        )
        self._queues: dict[str, tuple[Queue, Event]] = {}

    async def __aenter__(self) -> "MQTT":
        await self._client.__aenter__()
        await asyncio.gather(
            self._client.subscribe(ResultMessage.topic),
            self._client.subscribe(ScanStatusMessage.topic),
        )
        self._start()
        return self

    async def __aexit__(
        self,
        __exc_type: type[BaseException] | None,
        __exc_value: BaseException | None,
        __traceback: TracebackType | None,
    ) -> bool | None:
        for queue, event in self._queues.values():
            await event.wait()
            await queue.join()

        if not self._scan_status_task.done():
            self._scan_status_task.cancel()
        if not self._result_task.done():
            self._result_task.cancel()

        await asyncio.gather(
            self._scan_status_task, self._result_task, return_exceptions=True
        )
        await self._client.__aexit__(__exc_type, __exc_value, __traceback)

    def _start(self) -> None:
        self._result_task = asyncio.create_task(self._handle_result_messages())
        self._scan_status_task = asyncio.create_task(
            self._handle_scan_status_messages()
        )

    async def _handle_result_messages(self) -> None:
        async with self._client.filtered_messages(
            ResultMessage.topic
        ) as messages:
            async for message in messages:
                result_message: ResultMessage = ResultMessage.load(
                    message.payload
                )
                queue, _ = self._queues.get(result_message.scan_id)
                if queue:
                    queue.put_nowait(result_message)

    async def _handle_scan_status_messages(self) -> None:
        async with self._client.filtered_messages(
            ScanStatusMessage.topic
        ) as messages:
            async for message in messages:
                scan_status_message: ScanStatusMessage = ScanStatusMessage.load(
                    message.payload
                )
                _, event = self._queues.get(
                    scan_status_message.scan_id, (None, None)
                )
                if event and scan_status_message.status == ScanStatus.FINISHED:
                    event.set()

    async def start_scan(
        self,
        os_release: OSReleaseInfo,
        packages: list[str],
    ) -> str:
        scan_id = create_scan_id()
        message = ScanStartMessage(
            scan_id=scan_id,
            host_ip="",
            host_name="",
            os_release=get_notus_operating_system(os_release),
            package_list=packages,
        )

        self._queues[scan_id] = (Queue(), Event())

        await self._client.publish(message.topic, message.dump(), qos=1)

        return scan_id

    async def results(
        self, scan_id: str
    ) -> AsyncGenerator[ResultMessage, None]:
        queue, event = self._queues.get(scan_id, (None, None))
        if not queue:
            return

        while not event.is_set() or not queue.empty():
            queue_get = asyncio.create_task(queue.get())
            done, _ = await asyncio.wait(
                (queue_get, event.wait()), return_when=asyncio.FIRST_COMPLETED
            )
            if queue_get in done:
                message = await queue_get
                queue.task_done()
                yield message
