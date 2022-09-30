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

"""This file contains all functions that are related to
   text sanitization. This means that these functions try to
   remove or mitigate common errors in strings returned by
   vendor advisories.
   For example, some strings maybe contain trailing whitespaces
   or newlines. And some strings might contain characters that
   cannot be handled by our stack, so they get replaced.
"""

import logging
import re

logger = logging.getLogger(__name__)

MAX_FIELD_SIZE = 3000
# pylint: disable=line-too-long
PLACEHOLDER = "... [Please see the references for more information on the vulnerabilities]"
TRAILING_SPACE_BEFORE_NEWLINE_REGEX = re.compile(r"[ \t]+\r?\n")
REDUCE_MULTIPLE_WHITESPACES_TO_ONE = re.compile(r" +")
CVE_REGEX = re.compile(r"(CAN|CVE)-(?P<year>\d{4})-(?P<counter>\d+)")


def remove_trailing_spaces_and_carriage_returns(value: str) -> str:
    """Replace all carriage returns in a string with a newline.

    Arguments:
        value: The input string.

    Returns:
        The input string without any carriage returns.
    """
    no_trailing_spaces = TRAILING_SPACE_BEFORE_NEWLINE_REGEX.sub(r"\r\n", value)
    # Get rid of all carriage returns
    return "\n".join(no_trailing_spaces.splitlines())


def reduce_multiple_whitespaces_to_one(value: str) -> str:
    """Find all multiple occurrences of whitespaces and replace them
    with a single whitespace.

    Arguments:
        value: The input string.

    Returns:
        The sanitized input string without multiple whitespaces.
    """
    return REDUCE_MULTIPLE_WHITESPACES_TO_ONE.sub(" ", value)


def replace_quotation_marks(value: str) -> str:
    """Replace all occurrences of " with '.

    Arguments:
        value: The input string.

    Returns:
        The input string with single quotes instead of double quotes.
    """
    return value.replace('"', "'")


def replace_characters_disallowed_by_gvm(value: str) -> str:
    """Replace all characters that are disallowed by GVM with
    symbolic replacements.

    Arguments:
        value: The input string.

    Returns:
        The input string without disallowed characters.
    """
    # Disallowed chars due to limitations in GVM
    value = value.replace(";", ",")
    return value.replace("|", "<pipe>")


def sanitize_cves(cves: list[str] = None) -> list[str]:
    """Sanitize a list of CVEs.

    Arguments:
        cves: A list of CVE-IDs.

    Returns:
        The sanitized list of CVEs.
    """
    if not cves:
        return []

    sanitized_cves = set()
    # Sanitize each string individually
    for cve in cves:
        # Gets rid of extra spaces, parenthesis etc.
        # Also enforces the minimum 4 digits for the counter
        # and transforms deprecated CAN prefixes to CVE
        match = CVE_REGEX.search(cve)
        if match:
            sanitize_cve = (
                f"CVE-{match.group('year')}"
                f"-{match.group('counter').zfill(4)}"
            )

            sanitized_cves.add(sanitize_cve)
        else:
            logger.debug("CVE rejected; '%s'", cve)

    return sorted(list(sanitized_cves))


def limit_text_length(value: str) -> str:
    """Limit the text to the size and add placeholder,
    if text exceeds limit. The text won't be cut within a word,
    but at the closest whitespace inside the limit.

    Arguments:
        value: The input string.

    Returns:
        The cut string with placeholder, if necessary.
    """
    if len(value) > MAX_FIELD_SIZE:
        placeholder = " " + PLACEHOLDER
        limit = MAX_FIELD_SIZE - len(placeholder)
        # Find rightmost space
        cut_index = value[:limit].rfind(" ")
        if cut_index == -1:
            # Could not find it. Just hard-cut at the limit
            cut_index = limit
        else:
            # Found it! Move the cut_index to the left to remove
            # any possible other spaces
            while value[cut_index - 1] == " ":
                cut_index -= 1
        return f"{value[:cut_index]}{placeholder}"
    return value


def replace_tabs_with_spaces(value: str) -> str:
    """Replace all tabs (\t) with four spaces.

    Arguments:
        value: The input string.

    Returns:
        The input string with all tabs replaced.
    """
    return re.sub(r"\t", " ", value)


def basic_sanitization(value: str) -> str:
    """Calls replace_characters_disallowed_by_gvm, replace_tabs_with_spaces,
    and limit_text_length.

    Arguments:
        value: The input string.

    Returns:
        The sanitized input string.
    """
    if not value:
        return value

    tmp = replace_characters_disallowed_by_gvm(value)
    tmp = replace_tabs_with_spaces(tmp)
    tmp = limit_text_length(tmp)
    return tmp
