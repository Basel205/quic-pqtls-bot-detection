"""
Path bootstrap — import this at the top of any script to make all project
modules importable, regardless of which directory the script lives in.

Because the project directories use hyphens (traffic-gen, feature-extraction)
Python cannot import them as packages with dot notation. Instead we add each
subdirectory directly to sys.path so modules are importable by filename.

Usage (in any project script):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))  # own dir
    exec(open(str(Path(__file__).resolve().parents[?] / '_paths.py')).read())

Or simply call setup_paths() after locating the project root.
"""
import sys
from pathlib import Path


def setup_paths(project_root: Path | None = None) -> Path:
    """
    Add all project subdirectories to sys.path.
    Call once at the top of any script.
    Returns the project root Path.
    """
    if project_root is None:
        # Walk up from this file's location to find the project root
        here = Path(__file__).resolve().parent
        # _paths.py lives at project root
        project_root = here

    subdirs = [
        project_root / "feature-extraction",
        project_root / "traffic-gen",
        project_root / "capture",
        project_root / "detection-service",
        project_root / "ml",
        project_root / "db",
        project_root,  # for _paths itself and any root-level modules
    ]

    for d in subdirs:
        s = str(d)
        if s not in sys.path:
            sys.path.insert(0, s)

    return project_root
