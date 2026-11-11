# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Current filesystem-input inventory, separate from derivation/provenance labels."""
from collections.abc import Mapping
from pathlib import Path
import os

from bytefault.core.contracts import ContractError


def validate_files(files):
    if not isinstance(files, tuple) or any(not isinstance(p, str) or not p for p in files):
        raise ContractError('input_files', 'malformed', 'ordered tuple of nonempty filesystem paths required')
    return files


def inventory(*, files=(), options=()):
    """Inspect only explicitly supplied current files and current recipe options.

    No input reference, original request or ancestor is interpreted as a path.
    Missing files remain named inputs; metadata is used only to identify aliases
    and immediate seed-directory entries, never to require or read their bytes.
    """
    paths, directories = set(), set()
    def inspect(value):
        if isinstance(value, Mapping):
            if isinstance(value.get('path'), str):
                paths.add(Path(value['path']).resolve())
            paths.update(Path(p).resolve() for p in value.get('seed_files', ()) if isinstance(p, str))
            if isinstance(value.get('seed_directory'), str):
                directory = Path(value['seed_directory']).resolve()
                directories.add(directory)
                if directory.is_dir():
                    paths.update(p.resolve() for p in directory.iterdir() if p.is_file())
            for item in value.values(): inspect(item)
        elif isinstance(value, (tuple, list)):
            for item in value: inspect(item)
    try:
        paths.update(Path(p).resolve() for p in validate_files(files))
        inspect(options)
        return paths, directories
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, ContractError): raise
        raise ContractError('input_files', 'path_error', str(exc)) from exc


def aliases(output, paths, directories=()):
    target = Path(output)
    resolved = target.resolve()
    return (resolved in paths or resolved.parent in directories or target.parent.resolve() in directories or
        (resolved.exists() and any(p.exists() and resolved.samefile(p) for p in paths)))


def selected_scope_aliases(roots, paths):
    """Detect a selected local mutation scope containing a current input.

    Scan existing regular files so a hardlink inside a selected directory cannot
    be deleted after unrelated siblings. Linked directories are never traversed.
    """
    inputs = tuple(Path(path).resolve() for path in paths)
    if not inputs:
        return False
    def unreadable(error):
        raise error
    for selected in roots:
        root = Path(selected).resolve()
        if any(path == root or path.is_relative_to(root) for path in inputs):
            return True
        if root.is_file():
            if aliases(root, inputs):
                return True
        elif root.is_dir():
            for base, names, files in os.walk(root, onerror=unreadable):
                names[:] = [name for name in names if not (
                    (Path(base) / name).is_symlink() or (Path(base) / name).is_junction())]
                for name in files:
                    candidate = Path(base) / name
                    if not candidate.is_symlink() and aliases(candidate, inputs):
                        return True
    return False
