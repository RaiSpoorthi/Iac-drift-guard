"""Thin wrapper around the Terraform CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class TerraformError(RuntimeError):
    """A Terraform command failed."""


@dataclass
class PlanResult:
    exit_code: int  # 0 = infrastructure matches code, 2 = changes needed
    plan: dict

    @property
    def has_changes(self) -> bool:
        return self.exit_code == 2


class Terraform:
    def __init__(self, workdir: Path | str, env: dict[str, str] | None = None, binary: str = "terraform"):
        self.workdir = Path(workdir)
        resolved = shutil.which(binary)
        if resolved is None:
            raise TerraformError(
                f"'{binary}' was not found on PATH. Install Terraform: "
                "https://developer.hashicorp.com/terraform/install"
            )
        self.binary = resolved
        self.env = {**os.environ, "TF_IN_AUTOMATION": "1", **(env or {})}

    def _run(self, *args: str, ok_codes: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
        cmd = [self.binary, *args]
        proc = subprocess.run(cmd, cwd=self.workdir, env=self.env, text=True, capture_output=True)
        if proc.returncode not in ok_codes:
            raise TerraformError(
                f"`terraform {' '.join(args)}` exited with {proc.returncode}:\n{proc.stderr or proc.stdout}"
            )
        return proc

    def init(self) -> None:
        self._run("init", "-input=false", "-no-color")

    def apply(self) -> None:
        self._run("apply", "-input=false", "-auto-approve", "-no-color")

    def destroy(self) -> None:
        self._run("destroy", "-input=false", "-auto-approve", "-no-color")

    def plan(self, plan_file: str = "tfplan") -> PlanResult:
        """Refresh real state, compare it with the code, and return the JSON plan."""
        proc = self._run(
            "plan", "-input=false", "-no-color", "-detailed-exitcode", f"-out={plan_file}",
            ok_codes=(0, 2),
        )
        shown = self._run("show", "-json", plan_file)
        return PlanResult(exit_code=proc.returncode, plan=json.loads(shown.stdout))

    def outputs(self) -> dict[str, str]:
        proc = self._run("output", "-json")
        return {name: item["value"] for name, item in json.loads(proc.stdout).items()}
