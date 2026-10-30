import argparse
import sys
from .environment import inspect
from .experiments import run


def main():
    parser = argparse.ArgumentParser(description="iPerf2/iPerf3 traffic generation research")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--output", required=True)
    experiment = commands.add_parser("run")
    experiment.add_argument("config")
    experiment.add_argument("--output", required=True)
    analysis = commands.add_parser("analyze")
    analysis.add_argument("directory")
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            inspect(args.output)
            print(f"Environment saved: {args.output}")
        elif args.command == "run":
            run(args.config, args.output)
        else:
            from .analysis import analyze_all
            analyze_all(args.directory)
    except (RuntimeError, ValueError, TimeoutError, OSError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
