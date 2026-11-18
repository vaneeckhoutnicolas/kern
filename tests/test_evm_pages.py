# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026-2036 Nicolas Van Eeckhout (founder) and Kern contributors
"""The pages say what the Mini-EVM does.

README.md and the pages of the Mini-EVM described a machine with several
frames, the gas of the Yellow Paper and the instruction set a Solidity
compiler emits. The machine runs one program at a time, executes 44
instructions and three families, and has rules of its own. These tests
compare what the pages list with what the machine does, so that a page and
the machine do not drift apart again.

- Section 2.8 of docs/api-stability.md lists the instructions the machine
  executes, and the ones that have a price and are not executed.
- Section 2.10, and docs/multi-frame-evm.md, list the precompiles.
- Section 2.9 says that no gas is refunded and that a read of the storage
  costs the same each time.
- The fraud-proof example of README.md prints what its comments say.
- The pages no longer say what the machine does not do.

A test named `test_control_...` passed before the pages were corrected and
still does: it holds a fact about the machine that the pages now state.
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kern.evm import VmState, execute, step
from kern.evm import frames
from kern.evm.frames import FrameKind, WorldState, call_contract
from kern.evm.opcodes import GAS_COST, Op

STABILITY = ROOT / "docs" / "api-stability.md"
CALLS_PAGE = ROOT / "docs" / "multi-frame-evm.md"
README = ROOT / "README.md"

NUMBERS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
           "ten": 10, "eleven": 11, "twelve": 12}
FAMILIES = {"PUSH": int(Op.PUSH1), "DUP": int(Op.DUP1), "SWAP": int(Op.SWAP1)}


def section(path: Path, title: str) -> str:
    """The text of the section of `path` whose heading starts with `title`,
    up to the next heading of the same level."""
    text = path.read_text(encoding="utf-8")
    start = text.index(f"\n{title}")
    level = title.split(" ", 1)[0]
    end = text.find(f"\n{level} ", start + 1)
    return text[start:end if end != -1 else len(text)]


def rows(table_text: str) -> list:
    """The cells of each row of the markdown tables in `table_text`, without
    their header and separator rows."""
    found = []
    for line in table_text.splitlines():
        if line.startswith("|") and not set(line) <= set("|- "):
            found.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return found


def byte_of(name: str) -> int:
    family = re.fullmatch(r"(PUSH|DUP|SWAP)(\d+)", name)
    if family:
        return FAMILIES[family.group(1)] + int(family.group(2)) - 1
    return int(Op[name])


def named(listing: str) -> list:
    """The bytes a listing of a page names: `ADD, MUL` and `LOG0 to LOG4`."""
    found = []
    for item in re.split(r",\s*|\s+and\s+", listing):
        span = re.fullmatch(r"([A-Z]+)(\d+) to ([A-Z]+)(\d+)", item.strip())
        if span:
            assert span.group(1) == span.group(3), item
            found += [byte_of(f"{span.group(1)}{n}") for n in range(int(span.group(2)), int(span.group(4)) + 1)]
        elif item.strip():
            found.append(byte_of(item.strip()))
    return found


def after_one(byte: int) -> VmState:
    """The state after the machine is given `byte` as its one instruction,
    with a stack, a memory, a storage and gas that any instruction can use."""
    code = bytes([byte]) + bytes(40)
    return step(VmState(gas=10_000_000, stack=[1] * 20, memory=bytearray(64), storage={1: 1}), code)


def executed() -> set:
    """The bytes the machine executes: every one it does not halt on as an
    unknown instruction."""
    return {byte for byte in range(256) if "unknown opcode" not in (after_one(byte).last_error or "")}


# ---------------------------------------------------------------------------
# Section 2.8: the instructions
# ---------------------------------------------------------------------------

def the_listed_instructions() -> dict:
    table = rows(section(STABILITY, "### 2.8 "))
    assert table[0] == ["Group", "Instructions"]
    return {group: named(listing) for group, listing in table[1:]}


def test_the_instructions_section_2_8_lists_are_the_ones_the_machine_executes():
    listed = [byte for group in the_listed_instructions().values() for byte in group]
    assert len(listed) == len(set(listed)), "an instruction is listed twice"
    assert set(listed) == executed()


def test_section_2_8_counts_its_instructions():
    groups = the_listed_instructions()
    families = groups.pop("Families")
    alone = [byte for group in groups.values() for byte in group]
    said = re.search(r"executes (\d+) instructions and (\w+) families", section(STABILITY, "### 2.8 "))
    assert said and int(said.group(1)) == len(alone) and NUMBERS[said.group(2)] == 3
    assert len(families) == 32 + 16 + 16


def test_the_instructions_that_have_a_price_and_are_not_executed_are_the_ones_section_2_8_names():
    said = re.search(r"(\w+) instructions of Ethereum have a price in .*? and are not executed: ([^.]+)\.",
                     section(STABILITY, "### 2.8 "))
    assert said, "the sentence is not in section 2.8"
    listed = named(said.group(2))
    priced_and_not_executed = set(GAS_COST) - executed() - {int(Op.INVALID)}
    assert set(listed) == priced_and_not_executed
    assert NUMBERS[said.group(1).lower()] == len(listed) == len(priced_and_not_executed)


def test_control_an_instruction_that_is_not_executed_halts_the_machine_reverted():
    for byte in sorted(set(range(256)) - executed()):
        after = after_one(byte)
        assert after.halted and after.reverted, hex(byte)


# ---------------------------------------------------------------------------
# One program at a time
# ---------------------------------------------------------------------------

PUSH1 = int(Op.PUSH1)
WRITES = bytes([PUSH1, 9, PUSH1, 7, Op.SSTORE, Op.STOP])
CALLER, CALLING, CALLED = 0xAA, 0xCC, 0xBB


@pytest.mark.parametrize("name", ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"])
def test_control_a_program_cannot_call_another_program_nor_create_one(name):
    """Seven words are on the stack, the most any of these takes, and the
    contract it would call is there with a program that writes."""
    reaches_it = bytes([PUSH1, 0] * 5 + [PUSH1, CALLED, PUSH1, 0xFF, Op[name], Op.STOP])
    last = execute(reaches_it, gas=100_000).states[-1]
    assert last.halted and last.reverted and "unknown opcode" in last.last_error

    world = WorldState()
    world.get(CALLER).balance = 1_000
    world.get(CALLED).code = WRITES
    world.get(CALLING).code = reaches_it
    result = call_contract(world, kind=FrameKind.CALL, caller=CALLER, address=CALLING, value=0, calldata=b"",
                           gas=100_000)
    assert not result.success
    assert world.get(CALLED).storage == {} and world.get(CALLING).storage == {}


def test_control_the_contract_the_others_would_call_writes_when_it_is_called_from_outside():
    world = WorldState()
    world.get(CALLED).code = WRITES
    result = call_contract(world, kind=FrameKind.CALL, caller=CALLER, address=CALLED, value=0, calldata=b"",
                           gas=100_000)
    assert result.success and world.get(CALLED).storage == {7: 9}


@pytest.mark.parametrize("topics", range(5))
def test_control_a_program_emits_no_event(topics):
    emits = bytes([PUSH1, 0] * (2 + topics) + [Op.LOG0 + topics, Op.STOP])
    world = WorldState()
    world.get(CALLING).code = emits
    result = call_contract(world, kind=FrameKind.CALL, caller=CALLER, address=CALLING, value=0, calldata=b"",
                           gas=100_000)
    assert not result.success and result.logs == []


# ---------------------------------------------------------------------------
# Sections 2.9 and 2.10
# ---------------------------------------------------------------------------

def test_control_no_gas_is_refunded_for_emptying_a_slot():
    before = VmState(gas=100_000, stack=[0, 7], storage={7: 5})
    after = step(before, bytes([Op.SSTORE]))
    assert after.storage == {} and before.gas - after.gas == 5_000


def test_control_a_read_of_the_storage_costs_100_each_time():
    first = step(VmState(gas=100_000, stack=[7], storage={7: 5}), bytes([Op.SLOAD]))
    second = step(VmState(gas=first.gas, stack=[7], storage={7: 5}), bytes([Op.SLOAD]))
    assert (100_000 - first.gas, first.gas - second.gas) == (100, 100)


def test_section_2_9_says_what_the_two_tests_above_hold():
    text = section(STABILITY, "### 2.9 ")
    assert "No gas is refunded: emptying a slot costs 5,000 and gives nothing back." in text
    assert "A read of the storage (SLOAD) costs 100 each time" in text


def addresses_of(table_text: str) -> list:
    return [int(cells[0], 16) for cells in rows(table_text) if re.fullmatch(r"0x[0-9a-f]{2}", cells[0])]


def test_control_the_precompiles_of_section_2_10_are_the_ones_a_call_reaches():
    assert addresses_of(section(STABILITY, "### 2.10 ")) == sorted(frames.PRECOMPILES)


def test_the_precompiles_of_the_page_of_calls_are_the_ones_a_call_reaches():
    listed = addresses_of(section(CALLS_PAGE, "## Precompiles"))
    assert listed == sorted(frames.PRECOMPILES)
    said = re.search(r"it serves (\w+) precompiles", CALLS_PAGE.read_text(encoding="utf-8"))
    assert said and NUMBERS[said.group(1)] == len(listed)
    for address in listed:
        assert frames.is_precompile(address)
        result = call_contract(WorldState(), kind=FrameKind.CALL, caller=CALLER, address=address, value=0,
                               calldata=bytes(213), gas=100_000)
        assert isinstance(result.return_data, bytes), hex(address)


# ---------------------------------------------------------------------------
# The example of the README
# ---------------------------------------------------------------------------

def the_fraud_proof_example() -> str:
    text = README.read_text(encoding="utf-8")
    start = text.index("```python\n", text.index("## Try the fraud-proof protocol")) + len("```python\n")
    return text[start:text.index("```", start)]


def test_the_fraud_proof_example_of_the_readme_prints_what_its_comments_say():
    source = the_fraud_proof_example()
    announced = re.findall(r"^print\(.*\)\s+# (.+)$", source, flags=re.MULTILINE)
    assert len(announced) == 2, "the example no longer announces its result and its steps"
    printed = io.StringIO()
    with contextlib.redirect_stdout(printed):
        exec(compile(source, "README.md", "exec"), {})
    lines = printed.getvalue().splitlines()
    assert len(lines) == 4
    for line, comment in zip(lines, announced):
        assert line.endswith(comment.strip()), (line, comment)


# ---------------------------------------------------------------------------
# What the pages no longer say
# ---------------------------------------------------------------------------

PAGES = ["README.md", "docs/index.md", "docs/api-stability.md", "docs/multi-frame-evm.md", "docs/executive-summary.md",
         "docs/roadmap.md", "docs/setup-auditor.md", "docs/originality-and-attribution.md", "docs/legal-audit.md",
         "docs/whitepaper.md", "docs/building-the-site.md", "kern_site/whitepaper.html", "mkdocs.yml"]
WITHDRAWN = ["multi-frame", "Yellow Paper-compliant", "Yellow Paper compliance", "Yellow-Paper-equivalent",
             "matching Ethereum Yellow Paper", "Gas accounting matches Yellow Paper", "ethereum/tests opcode subset",
             "the same subset used by Solidity", "kern/vm_gas.py"]


@pytest.mark.parametrize("page", PAGES)
def test_a_page_no_longer_says_what_the_machine_does_not_do(page):
    """The name of the file docs/multi-frame-evm.md stays, so that links to
    it hold: it is set aside before the page is read."""
    text = (ROOT / page).read_text(encoding="utf-8").replace("multi-frame-evm", "")
    said = [phrase for phrase in WITHDRAWN if phrase.lower() in text.lower()]
    assert not said, said


def test_the_page_of_calls_says_one_program_at_a_time():
    text = CALLS_PAGE.read_text(encoding="utf-8")
    assert text.startswith("# Calls, creations and precompiles of the Mini-EVM\n")
    for sentence in ("A contract cannot call another contract, and there is no stack of frames.",
                     "No call from inside a program.",
                     "No event."):
        assert sentence in text, sentence
    assert "pushes a frame" not in text and "real DeFi" not in text


def test_the_page_of_fraud_proofs_describes_the_machine_of_today():
    text = (ROOT / "docs" / "evm-fraud-proofs.md").read_text(encoding="utf-8")
    assert "30+ opcodes" not in text and "19 tests" not in text and "DUP1..4" not in text
    assert "the nine fields of a state" in text
    assert "❌ Calls (CALL / DELEGATECALL / STATICCALL) — single-frame execution only." in text
    assert "❌ Storage (SSTORE / SLOAD)" not in text


def test_the_page_of_rollups_lists_what_the_model_has_today():
    text = (ROOT / "docs" / "rollups.md").read_text(encoding="utf-8")
    assert "The rollup framework is a model, off the chain" in text
    for outdated in ("❌ Interactive bisection protocol", "❌ Single-step EVM verifier", "❌ Forced-inclusion path",
                     "not yet implemented in v0.2"):
        assert outdated not in text, outdated


def test_the_white_paper_names_the_rollup_of_solidity_contracts_as_a_target():
    paper = (ROOT / "docs" / "whitepaper.md").read_text(encoding="utf-8")
    summary = (ROOT / "docs" / "executive-summary.md").read_text(encoding="utf-8")
    assert "That home is a target, not a product." in paper and "Neither is built." in paper
    assert "Developers use Hardhat, Foundry, MetaMask" not in paper
    assert "Solidity contracts run on" not in paper
    assert "working unchanged" not in summary and "That is not built" in summary


def test_the_white_paper_of_the_site_is_the_white_paper_of_the_documentation():
    page = (ROOT / "kern_site" / "whitepaper.html").read_text(encoding="utf-8")
    assert "That home is a target, not a product." in page and "Neither is built." in page
    assert "Developers use Hardhat, Foundry, MetaMask" not in page
