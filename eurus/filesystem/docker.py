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

import json
import logging
import os
from collections import OrderedDict
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from tarfile import TarFile, TarInfo
from types import MappingProxyType, TracebackType
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Iterable,
    Iterator,
    Mapping,
    Optional,
    Sequence,
    Union,
)

import httpx

from eurus.filesystem import File, FileSystem

DEFAULT_DOCKER_SOCKET = "/var/run/docker.sock"

logger = logging.getLogger(__name__)


def repo_split(name: str) -> tuple[str, str]:
    image = name.rsplit(":", maxsplit=1)
    if isinstance(image, list):
        return image
    return image, "latest"


class DockerImageEntry:
    def __init__(self, layer: "DockerImageLayer", tarinfo: TarInfo):
        self._layer = layer
        self._tarinfo = tarinfo
        self._path = None

    @property
    def name(self) -> str:
        return self._tarinfo.name

    @property
    def non_whiteout_name(self) -> str:
        if not self.is_whiteout():
            return self.name

        return str(self.path.parent / self.path.name[4:])

    @property
    def path(self) -> Path:
        if self._path is None:
            self._path = Path(self._tarinfo.name)

        return self._path

    def is_whiteout(self) -> bool:
        return self.path.name.startswith(".wh.")

    def extract(self) -> File:
        return self._layer.extract(self)

    def __fspath__(self) -> str:
        return self._tarinfo.name

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.name!r} at {id(self):#x}>"


class DockerImageLayer:
    def __init__(self, layer_id: str, tarball: TarFile) -> None:
        self._tarball = tarball
        self._id = layer_id

    def extract(self, entry: DockerImageEntry) -> File:
        # pylint: disable=protected-access
        return self._tarball.extractfile(entry._tarinfo)  # type: ignore

    def __iter__(self) -> Iterator[DockerImageEntry]:
        for tarinfo in self._tarball:
            yield DockerImageEntry(self, tarinfo)

    def __str__(self) -> str:
        return self._id

    def __repr__(self):
        return f"<{self.__class__.__name__} {self._id!r} at {id(self):#x}>"


class DockerArchive(FileSystem):
    """
    Class for the docker archive format v1.2

    https://github.com/moby/moby/blob/master/image/spec/v1.2.md
    """

    def __init__(self, path: os.PathLike):
        self._tarball = TarFile(path)
        self._initialized = False
        self._config = None
        self._layers = OrderedDict()
        self._entries = OrderedDict()

        self._init()

    def _extract_file(self, file: Union[TarInfo, str]) -> File | None:
        return self._tarball.extractfile(file)  # type: ignore

    def _extract_json(self, file: Union[TarInfo, str]) -> Dict[str, Any] | None:
        tar_file = self._extract_file(file)
        return json.load(tar_file) if tar_file else None

    def _init(self):
        if self._initialized:
            return

        manifests: Sequence[dict[str, str]] | None = self._extract_json(  # type: ignore
            "manifest.json"
        )
        # get first manifest not sure why there are more then one
        self._manifest = manifests[0]

        config_file = self._manifest.get("Config")

        # not sure if there might be no config
        if config_file:
            self._config = self._extract_json(config_file)

        for layer_file_name in self._manifest.get("Layers", []):
            fileobj = self._extract_file(layer_file_name)

            layer_path = Path(layer_file_name)
            layer_id = layer_path.parts[0]

            layer_tarball = TarFile(fileobj=fileobj)
            docker_layer = DockerImageLayer(layer_id, layer_tarball)

            self._layers[layer_id] = docker_layer

            for entry in docker_layer:
                if entry.is_whiteout():
                    try:
                        del self._entries[entry.non_whiteout_name]
                        logger.debug(
                            "Whiteout %s in layer %s from image %s",
                            entry.non_whiteout_name,
                            docker_layer,
                            self.tags,
                        )
                    except KeyError:
                        logger.warning(
                            "Can't whiteout %s in layer %s from image %s",
                            entry.non_whiteout_name,
                            docker_layer,
                            self.tags,
                        )
                else:
                    self._entries[entry.name] = entry

        self._initialized = True

    @property
    def entries(self) -> Mapping[str, DockerImageEntry]:
        return MappingProxyType(self._entries)

    @property
    def layers(self) -> Mapping[str, DockerImageLayer]:
        return MappingProxyType(self._layers)

    @property
    def config(self) -> Mapping[str, Any]:
        return MappingProxyType(self._config or {})

    @property
    def manifest(self) -> Mapping[str, Any]:
        return MappingProxyType(self._manifest)

    @property
    def tags(self) -> Iterable[str]:
        return self._manifest.get("RepoTags", [])

    def get(self, name: str) -> File | None:
        if name.startswith("/"):
            # remove root slash
            name = name[1:]

        entry = self.entries.get(name)
        if not entry:
            return None

        return entry.extract()


class DockerImages:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def list(self) -> Iterable[Dict]:
        response = await self._client.get("http://docker.com/images/json")
        response.raise_for_status()
        return response.json()

    async def inspect(self, name: str) -> Dict:
        response = await self._client.get(
            f"http://docker.com/images/{name}/json"
        )
        response.raise_for_status()
        return response.json()

    async def get(self, name: str) -> AsyncIterator[bytes]:
        async with self._client.stream(
            "GET", f"http://docker.com/images/{name}/get"
        ) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes():
                yield chunk

    async def pull(self, name: str):
        image, tag = repo_split(name)

        data = {"tag": tag, "fromImage": image}
        response = await self._client.post(
            "http://docker.com/images/create", params=data
        )
        response.raise_for_status()


class Docker(AbstractAsyncContextManager):
    def __init__(self):
        transport = httpx.AsyncHTTPTransport(uds=DEFAULT_DOCKER_SOCKET)
        timeout = httpx.Timeout(30.0, connect=60.0)
        self._client = httpx.AsyncClient(
            transport=transport, timeout=timeout, http2=True
        )
        self.images = DockerImages(self._client)

    async def __aenter__(self) -> "Docker":
        return self

    async def __aexit__(
        self,
        __exc_type: Optional[type[BaseException]],
        __exc_value: Optional[BaseException],
        __traceback: Optional[TracebackType],
    ) -> bool | None:
        await self.aclose()

    async def aclose(self):
        await self._client.aclose()
