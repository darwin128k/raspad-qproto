#!/usr/bin/env python3
"""Short GitHub release notes: blurb + bullets + collapsible changelog."""
import argparse

def changelog_for(path: str, ver: str) -> str:
    lines = open(path, encoding="utf-8").read().splitlines()
    blocks, cur = [], []
    for line in lines:
        if line.startswith("## "):
            if cur:
                blocks.append(cur)
            cur = [line]
        elif cur:
            cur.append(line)
    if cur:
        blocks.append(cur)

    def text(b):
        return "\n".join(b).strip()

    for b in blocks:
        if b[0].startswith(f"## [{ver}]"):
            return text(b)
    for b in blocks:
        body = "\n".join(b[1:]).strip()
        if not body:
            continue
        if b[0].startswith("## [Unreleased]"):
            return f"## [{ver}]\n\n{body}"
        return text(b)
    return ""

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tag", required=True)
    p.add_argument("--package", required=True)
    p.add_argument("--highlight", action="append", default=[])
    p.add_argument("--changelog", default="CHANGELOG.md")
    args = p.parse_args()
    ver = args.tag[1:] if args.tag.startswith("v") else args.tag
    print("## Package\n")
    print(args.package)
    print()
    print("## What's in this release\n")
    for h in args.highlight:
        print(f"- {h}")
    print()
    cl = changelog_for(args.changelog, ver)
    if cl:
        print("<details>")
        print("<summary>Full changelog</summary>\n")
        print(cl)
        print("\n</details>")
        print()

if __name__ == "__main__":
    main()
