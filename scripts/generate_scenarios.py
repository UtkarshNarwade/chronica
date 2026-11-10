"""CLI script to generate or reset synthetic scenarios and ground truth."""

from pathlib import Path
import sys

# Ensure repository root is in sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from synthetic_data.generator import ScenarioGenerator


def main() -> None:
    data_dir = repo_root / "synthetic_data"
    generator = ScenarioGenerator(output_root=data_dir)
    print(f"Generating synthetic forensic scenarios into: {data_dir}")
    results = generator.generate_all()

    for name, (scen_dir, gt_file) in results.items():
        print(f"  [+] {name}:")
        print(f"      Evidence Folder: {scen_dir}")
        print(f"      Ground Truth:    {gt_file}")
    print("\nAll 3 synthetic scenarios generated successfully!")


if __name__ == "__main__":
    main()
