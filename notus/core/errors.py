# -*- coding: utf-8 -*-
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


class NotusError(Exception):
    """Base error class for notus exceptions."""


class AdvisoriesIOError(NotusError):
    """Error class for issues during reading or writing advisories
    information.
    """


class ProductsIOError(NotusError):
    """Error class for issues during reading or writinga products
    information.
    """


class MessageParsingError(NotusError):
    """A problem while parsing an message"""
