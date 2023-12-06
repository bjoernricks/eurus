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
from typing import AsyncContextManager, AsyncIterator
from uuid import uuid4

from aiomqtt import Client, ProtocolVersion
from aiomqtt import Message as MQTTMessage

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
        self._queues: dict[str, tuple[Queue[ResultMessage], Event]] = {}

    async def __aenter__(self) -> "MQTT":
        await self._client.__aenter__()
        self._message_task = asyncio.create_task(self._start())
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

        if not self._message_task.done():
            self._message_task.cancel()

        try:
            await self._message_task
        except asyncio.CancelledError:
            pass

        await self._client.__aexit__(__exc_type, __exc_value, __traceback)

    async def _start(self) -> None:
        async with self._client.messages() as messages:
            await self._client.subscribe(ResultMessage.topic)
            await self._client.subscribe(ScanStatusMessage.topic)

            async for message in messages:
                if message.topic.matches(ResultMessage.topic):
                    self._handle_result_message(message)
                if message.topic.matches(ScanStatusMessage.topic):
                    self._handle_scan_status_messages(message)

    def _handle_result_message(self, message: MQTTMessage) -> None:
        result_message: ResultMessage = ResultMessage.load(message.payload)  # type: ignore
        queue, _ = self._queues[result_message.scan_id]
        if queue:
            queue.put_nowait(result_message)

    def _handle_scan_status_messages(self, message: MQTTMessage) -> None:
        scan_status_message: ScanStatusMessage = ScanStatusMessage.load(
            message.payload  # type: ignore
        )
        _, event = self._queues.get(scan_status_message.scan_id, (None, None))
        if event and scan_status_message.status == ScanStatus.FINISHED:
            event.set()

    async def start_scan(
        self,
        host_name: str,
        os_release: OSReleaseInfo,
        packages: list[str],
    ) -> str:
        scan_id = create_scan_id()
        message = ScanStartMessage(
            scan_id=scan_id,
            host_ip="",
            host_name=host_name,
            os_release=get_notus_operating_system(os_release),
            package_list=packages,
        )

        self._queues[scan_id] = (Queue(), Event())

        await self._client.publish(message.topic, message.dump(), qos=1)

        return scan_id

    async def results(self, scan_id: str) -> AsyncIterator[ResultMessage]:
        queue, event = self._queues.get(scan_id, (None, None))
        if not queue or not event:
            return

        while not event.is_set() or not queue.empty():
            queue_get = asyncio.create_task(queue.get())
            event_wait = asyncio.create_task(event.wait())
            done, _ = await asyncio.wait(
                (queue_get, event_wait), return_when=asyncio.FIRST_COMPLETED
            )
            if queue_get in done:
                message = await queue_get
                queue.task_done()
                yield message
