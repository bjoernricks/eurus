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
from enum import Enum

from ..errors import MessageParsingError
from .message import (
    Message,
    MessageParsedType,
    MessageSerializedType,
    MessageType,
)


class ResultType(Enum):
    ALARM = "ALARM"


@dataclass(frozen=True, kw_only=True)
class ResultMessage(Message):
    message_type: MessageType = MessageType.RESULT
    topic: str = "scanner/scan/info"

    scan_id: str
    host_ip: str
    host_name: str
    oid: str
    value: str
    port: str = "package"
    uri: str = None
    result_type: ResultType = ResultType.ALARM

    def serialize(self) -> MessageSerializedType:
        message = super().serialize()
        message.update(
            {
                "scan_id": self.scan_id,
                "host_ip": self.host_ip,
                "host_name": self.host_name,
                "oid": self.oid,
                "value": self.value,
                "port": self.port,
                "uri": self.uri,
                "result_type": self.result_type.value,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: MessageSerializedType) -> MessageParsedType:
        kwargs = super()._parse(data)
        try:
            kwargs.update(
                {
                    "scan_id": data.get("scan_id"),
                    "host_ip": data.get("host_ip"),
                    "host_name": data.get("host_name"),
                    "oid": data.get("oid"),
                    "value": data.get("value"),
                    "port": data.get("port"),
                    "uri": data.get("uri"),
                    "result_type": ResultType(data.get("result_type")),
                }
            )
        except ValueError as e:
            raise MessageParsingError(
                f"error while parsing 'result_type', {e}"
            ) from e
        return kwargs
