#!/bin/sh
# Writes git's own archives of one small tree, which hold's writers must
# reproduce byte for byte (src/testing/git_test.zig): relic's `git archive`
# writes through them. Run by hand from the repository's root.
set -eu
out=$(pwd)/testdata/git
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
git init -q repo
cd repo
printf 'hello\n' > README
printf '#!/bin/sh\necho x\n' > run.sh; chmod 755 run.sh
mkdir -p dir
printf 'in a directory\n' > dir/file
ln -s dir/file link
# A path a ustar header holds only split at a slash.
deep=$(printf 'd%.0s' $(seq 1 60))/$(printf 'e%.0s' $(seq 1 60))
mkdir -p "$deep"
printf 'deep\n' > "$deep/$(printf 'f%.0s' $(seq 1 60)).txt"
# A name no split fits: a pax path, the header named <oid>.data.
long=$(printf 'n%.0s' $(seq 1 120))
printf 'long\n' > "$long"
# A link target past 100 bytes: a pax linkpath.
ln -s "$(printf 't%.0s' $(seq 1 110))" longlink
git add -A
GIT_AUTHOR_DATE=2020-01-02T03:04:05Z GIT_COMMITTER_DATE=2020-01-02T03:04:05Z \
  git -c user.name=hold -c user.email=hold@example.com commit -q -m tree
git archive --format=tar HEAD > "$out/tree.tar"
git archive --format=zip -0 HEAD > "$out/tree-store.zip"
git rev-parse HEAD > "$out/commit"
git ls-tree -r -t --full-tree HEAD > "$out/tree.ls"
git --version > "$out/git-version"
