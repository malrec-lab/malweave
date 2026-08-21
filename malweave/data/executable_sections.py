
"""
Identify the regions of a PE executable that are executable.

See https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
  for more information on the section headers in a PE file.
"""

from __future__ import annotations
from argparse import ArgumentParser
from collections.abc import Iterable
from collections import Counter, namedtuple, OrderedDict
from enum import Enum, IntFlag, auto
from itertools import islice, repeat, tee
import json
import multiprocessing as mp
import os
from pathlib import Path
from pprint import pformat, pprint
import sys
import tempfile
import time
from typing import Literal, Optional
import zipfile

# pylint: disable=wrong-import-position
if __name__ == "__main__":
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
# pylint: enable=wrong-import-position

try:
    import lief
    lief.logging.disable()  # pylint: disable=no-member,c-extension-no-member
except (ModuleNotFoundError, ImportError):
    print("WARNING: lief is not available.")
try:
    import pefile
except (ModuleNotFoundError, ImportError):
    print("WARNING: pefile is not available.")
from tqdm import tqdm

from malweave.data.io import get_data_from_archives


SectionSummary = namedtuple("SectionSummary", ("offset", "size", "is_executable"))
Boundaries = list[tuple[int, int]]


class Toolkit(Enum):
    PEFILE = "pefile"
    LIEF   = "lief"


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE    = 0x00000020


def set_pefile_flags():
    global IMAGE_SCN_MEM_EXECUTE  # pylint: disable=global-statement
    global IMAGE_SCN_CNT_CODE     # pylint: disable=global-statement

    for char, code in pefile.section_characteristics:
        if char == "IMAGE_SCN_MEM_EXECUTE":
            IMAGE_SCN_MEM_EXECUTE = code
        if char == "IMAGE_SCN_CNT_CODE":
            IMAGE_SCN_CNT_CODE = code


class ExitCode(IntFlag):
    SUCCESS                     = auto()
    COULD_NOT_PARSE             = auto()
    NO_SECTIONS_FOUND           = auto()
    NO_NONEMPTY_SECTIONS_FOUND  = auto()
    NO_EXECUTABLE_SECTION_FOUND = auto()
    SECTION_OVER_FILE_BOUNDARY  = auto()
    SECTION_OVER_NEXT_SECTION   = auto()
    SECTION_EMPTY               = auto()
    SECTION_LOWER_OVER_UPPER    = auto()


class GetExecutableSectionBounds:
    """
    Extract section boundaries of a PE file that are executable.

    Arguments:
     (file): The path to the PE file to analyze. Optional if `content` is provided.
     (content): The content of the PE file to analyze. Optional if `file` is provided.
     (toolkit): The toolkit ("lief" or "pefile") to analysze the binary with.
      The values returned are identicail regardless of the toolkit used. The
      primary difference is the fact that lief is ~50x faster.

    Raises:
     (FileNotFoundError): If the input file does not exist.
     (ValueError): If an invalid `toolkit` is provided.

    Returns:
     (Boundaries): A list of (upper, lower) tuples indicating the boundaries of
      the PE file that are marked as executable or containing code. Note that
      the lower bound is inclusive whereas the upper is exclusive (for slicing).
     (ExitCode): Flag indicating the issues (if any) encountered during analysis.

    Usage:
     >>> bounds, error = GetExecutableSectionBounds(file)()
    """

    def __init__(
        self,
        file: Optional[str] = None,
        content: Optional[bytes] = None,
        toolkit: Toolkit | str = Toolkit("lief"),
    ) -> None:
        if (file is not None) == (content is not None):
            raise ValueError("One and only one of `file` or `content` must be provided.")

        self.file = file
        self.content = Path(file).read_bytes() if content is None else content
        self.toolkit = Toolkit(toolkit)
        self.length = len(content) if file is None else os.path.getsize(file)

    def __call__(self) -> tuple[Boundaries, ExitCode]:
        if self.toolkit == Toolkit.LIEF:
            return self._get_boundaries_lief()
        if self.toolkit == Toolkit.PEFILE:
            return self._get_boundaries_pefile()
        raise TypeError(f"{type(self.toolkit)}")

    def _get_boundaries_lief(self) -> tuple[Boundaries, ExitCode]:
        binary = lief.parse(self.content)  # pylint: disable=no-member,c-extension-no-member
        if binary is None:
            return [], ExitCode.COULD_NOT_PARSE

        summaries = self._get_summaries_lief(binary)
        if not summaries:
            return [], ExitCode.NO_SECTIONS_FOUND

        summaries = [s for s in summaries if s.size > 0]
        if not summaries:
            return [], ExitCode.NO_NONEMPTY_SECTIONS_FOUND

        if not any(summary.is_executable for summary in summaries):
            return [], ExitCode.NO_EXECUTABLE_SECTION_FOUND

        return self._analyze_section_summaries(summaries)

    def _get_boundaries_pefile(self) -> tuple[Boundaries, ExitCode]:
        try:
            binary = pefile.PE(data=self.content)
        except pefile.PEFormatError:
            return [], ExitCode.COULD_NOT_PARSE

        summaries = self._get_summaries_pefile(binary)
        if not summaries:
            return [], ExitCode.NO_SECTIONS_FOUND

        summaries = [s for s in summaries if s.size > 0]
        if not summaries:
            return [], ExitCode.NO_NONEMPTY_SECTIONS_FOUND

        if not any(summary.is_executable for summary in summaries):
            return [], ExitCode.NO_EXECUTABLE_SECTION_FOUND

        return self._analyze_section_summaries(summaries)

    @staticmethod
    def _get_summaries_lief(binary: lief.PE.Binary) -> list[SectionSummary]:
        summaries: list[SectionSummary] = []
        for section in binary.sections:
            offset = section.offset
            size = section.size
            is_executable = GetExecutableSectionBounds._is_executable_section_lief(section)
            summary = SectionSummary(offset, size, is_executable)
            summaries.append(summary)
        return summaries

    @staticmethod
    def _get_summaries_pefile(binary: pefile.PE) -> list[SectionSummary]:
        summaries: list[SectionSummary] = []
        for section in binary.sections:
            offset = section.PointerToRawData
            size = section.SizeOfRawData
            is_executable = GetExecutableSectionBounds._is_executable_section_pefile(section)
            summary = SectionSummary(offset, size, is_executable)
            summaries.append(summary)
        return summaries

    @staticmethod
    def _is_executable_section_lief(section: lief.PE.Section) -> bool:
        for c in section.characteristics_lists:
            c = str(c)
            if "MEM_EXECUTE" in c:
                return True
            if "CNT_CODE" in c:
                return True
        return False

    @staticmethod
    def _is_executable_section_pefile(section: pefile.SectionStructure) -> bool:
        characteristics = section.Characteristics
        if characteristics & IMAGE_SCN_MEM_EXECUTE:
            return True
        if characteristics & IMAGE_SCN_CNT_CODE:
            return True
        return False

    def _analyze_section_summaries(self, summaries: list[SectionSummary]) -> tuple[Boundaries, ExitCode]:
        exit_code = ExitCode(0)
        boundary: Boundaries = []
        for prv, cur, nxt in zip([None] + summaries[:-1], summaries, summaries[1:] + [None]):
            if not cur.is_executable:
                continue

            (lower, upper), code = self._get_section_bounds(prv, cur, nxt, self.length)
            exit_code = exit_code | code

            # Do not add to boundaries list and do not trigger unsuccessful exit code.
            if ExitCode.SECTION_EMPTY & code:
                continue
            if ExitCode.SECTION_LOWER_OVER_UPPER & code:
                continue

            boundary.append((lower, upper))

        if exit_code == ExitCode(0):
            exit_code = ExitCode.SUCCESS

        return boundary, exit_code

    @staticmethod
    def _get_section_bounds(
        prv: Optional[SectionSummary],  # pylint: disable=unused-argument
        cur: SectionSummary,
        nxt: Optional[SectionSummary],
        length: int,
    ) -> tuple[tuple[int, int], ExitCode]:
        code = ExitCode(0)
        lower = cur.offset
        upper = cur.offset + cur.size

        if upper > length:
            upper = length
            code = code | ExitCode.SECTION_OVER_FILE_BOUNDARY

        if nxt is not None and upper > nxt.offset:
            upper = nxt.offset
            code = code | ExitCode.SECTION_OVER_NEXT_SECTION

        if lower == upper:
            code = code | ExitCode.SECTION_EMPTY

        if lower > upper:
            code = code | ExitCode.SECTION_LOWER_OVER_UPPER

        return (lower, upper), code


def get_executable_section_bounds(
    file: Optional[str] = None,
    content: Optional[bytes] = None,
    toolkit: Toolkit | str = Toolkit.LIEF,
) -> tuple[Boundaries, ExitCode]:
    return GetExecutableSectionBounds(file, content, toolkit)()


def get_executable_section(
    file: Optional[str] = None,
    content: Optional[bytes] = None,
    toolkit: Toolkit | str = Toolkit.LIEF,
) -> Optional[bytes]:
    content = Path(file).read_bytes() if content is None else content
    function = GetExecutableSectionBounds(None, content, toolkit)
    bounds, _ = function()
    exe = b""
    for lower, upper in bounds:
        if lower < 0 or upper > len(content):
            continue
        exe += content[lower:upper]
    if not exe:
        return None
    return exe


class Runner:

    # Time for 1024 files:
      # num_workers=1: 110
      # num_workers=2:  92
      # num_workers=4:  92

    def __init__(
        self,
        files: Optional[Iterable[str]] = repeat(None),
        contents: Optional[Iterable[bytes]] = repeat(None),
        names: Optional[Iterable[str]] = repeat(None),
        toolkit: Toolkit = Toolkit.LIEF,
        num_workers: Optional[int] = None,
    ) -> None:
        self.files = files
        self.contents = contents
        self.names = names
        self.toolkit = toolkit
        self.num_workers = num_workers

    def __call__(self, total: Optional[int] = None) -> dict[str, tuple[Boundaries, ExitCode]]:
        iterable = zip(self.files, self.contents, self.names, repeat(self.toolkit))

        if self.num_workers is not None and self.num_workers > 1:
            with mp.Pool(self.num_workers) as pool:
                name_boundaries_error = list(pool.imap(Runner.get_executable_section_bounds, iterable))
        else:
            name_boundaries_error = [Runner.get_executable_section_bounds(i) for i in tqdm(iterable, total=total)]

        d = {name: {"bounds": bounds, "return": error.name} for name, bounds, error in name_boundaries_error}
        d = OrderedDict(sorted(d.items(), key=lambda x: x[0]))
        return d

    @staticmethod
    def get_executable_section_bounds(args: tuple) -> tuple[str, Boundaries, ExitCode]:
        file, content, name, toolkit = args
        bounds, error = GetExecutableSectionBounds(file, content, toolkit)()
        return name, bounds, error


def main():
    parser = ArgumentParser()
    parser.add_argument("--outfile", type=Path, required=True)
    parser.add_argument("--inarchives", type=Path, required=True)
    parser.add_argument("--toolkit", type=Toolkit, default="lief")
    parser.add_argument("--num_workers", type=int, default=1)
    parser.add_argument("--subset", type=int, default=None)
    args = parser.parse_args()

    print(f"args={pformat(args.__dict__)}")

    archives = sorted(args.inarchives.rglob("*.zip"))
    names = islice((n for n, _ in get_data_from_archives(archives, names=True, contents=False)), args.subset)
    contents = islice((c for _, c in get_data_from_archives(archives, names=False, contents=True)), args.subset)

    total = args.subset
    if total is None and (args.num_workers is None or args.num_workers < 2):
        total = 0
        for f in archives:
            with zipfile.ZipFile(f, "r") as zp:
                total += len(zp.namelist())

    t_i = time.time()

    exe_map = Runner(
        contents=contents,
        names=names,
        toolkit=args.toolkit,
        num_workers=args.num_workers
    )(total)

    t_f = time.time()

    print(f"Time taken: {t_f - t_i:.2f} seconds")

    with open(args.outfile, "w") as fp:
        fp.write(json.dumps(exe_map, indent=4))


if __name__ == "__main__":
    main()
