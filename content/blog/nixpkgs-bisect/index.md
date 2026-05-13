+++
title = "fun bisecting nixpkgs"
date = 2026-05-12
+++

After updating some stuff on my Raspberry Pi and trying to deploy a new NixOS
generation, I encountered this build error:

```
$ nixos-rebuild switch --flake .#rpi --target-host home --sudo
[..]
error: Cannot build '/nix/store/2j8nsb924fjw7vgkrsmhi9k1fs3jka58-bisca-backend-aarch64-unknown-linux-gnu-0.1.0.drv'.
       Reason: builder failed with exit code 101.
       Output paths:
         /nix/store/80qy9xhbqhr9vrw50jylzakhcbm83a4b-bisca-backend-aarch64-unknown-linux-gnu-0.1.0
[..]
       >   cargo:warning=aarch64-unknown-linux-gnu-gcc: error: unrecognized command-line option '-m64'
       >
       >   --- stderr
       >
       >
       >   error occurred in cc-rs: command did not execute successfully (status code exit status: 1): LC_ALL="C" "aarch64-unknown-linux-gnu-gcc" "-O0" "-ffunction-sections" "-fdata-sections" "-fPIC" "-m64" "-w" "-DSQLITE_CORE" "-DSQLITE_DEFAULT_FOREIGN_KEYS=1" "-DSQLITE_ENABLE_API_ARMOR" "-DSQLITE_ENABLE_COLUMN_METADATA" "-DSQLITE_ENABLE_DBSTAT_VTAB" "-DSQLITE_ENABLE_FTS3" "-DSQLITE_ENABLE_FTS3_PARENTHESIS" "-DSQLITE_ENABLE_FTS5" "-DSQLITE_ENABLE_JSON1" "-DSQLITE_ENABLE_LOAD_EXTENSION=1" "-DSQLITE_ENABLE_MEMORY_MANAGEMENT" "-DSQLITE_ENABLE_RTREE" "-DSQLITE_ENABLE_STAT2" "-DSQLITE_ENABLE_STAT4" "-DSQLITE_SOUNDEX" "-DSQLITE_THREADSAFE=1" "-DSQLITE_USE_URI" "-DHAVE_USLEEP=1" "-D_POSIX_THREAD_SAFE_FUNCTIONS" "-DHAVE_ISNAN" "-DHAVE_LOCALTIME_R" "-DSQLITE_ENABLE_UNLOCK_NOTIFY" "-o" "/build/backend/target/release/build/libsqlite3-sys-a4661d61eaf4765c/out/c877a2978823c39d-sqlite3.o" "-c" "sqlite3/sqlite3.c"
       >
       >
       > warning: build failed, waiting for other jobs to finish...
       For full logs, run:
         nix log /nix/store/2j8nsb924fjw7vgkrsmhi9k1fs3jka58-bisca-backend-aarch64-unknown-linux-gnu-0.1.0.drv
```

Now, the inner details of bisca are not really interesting here.
What's relevant is that it is a Rust service which needs to be deployed on an
aarch64 rpi zero, and since it's some private stuff I wrote, there's of course
no cached package on cache.nixos.org. And since I can't really build it on the
rpi due to CPU/memory constraints, I need to cross compile it on my laptop.

For that there are a couple of options: emulate a full aarch64 system with QEMU
binfmt (slow) or do proper cross compilation with x86_64 native compilers that
produce aarch64. Here I'm going for the latter:

```
{
  config,
  bisca,
  lib,
  pkgs,
  ...
}:
let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  system = pkgs.stdenv.hostPlatform.system;

  crossPkgs = import bisca.inputs.nixpkgs {
    localSystem = buildSystem;
    crossSystem = system;
    overlays = [ bisca.overlays.default ];
  };
in
{
  # ..

  services = {
    bisca = {
      enable = true;
      backend.package = crossPkgs.bisca-backend;
    };
}
```

Enough context, let's go back to the actual issue. Given this is my first time
dealing with a random failure after bumping `nixpkgs`, I have to first figure
out a way to debug it, which is what this write-up is all about.

## The plan: bisect all the things

The initial plan was almost naive: run git bisect on `nixpkgs`, with the
`$LAST_WORKING_REV` from my `nix-config` as good commit and `nixpkgs-unstable`
as bad commit. Then, for each commit try to build bisca pointing its `nixpkgs`
input to my local repo where I was bisecting:

```
$ nix build ~/nix-config#nixosConfigurations.rpi.config.services.bisca.backend.package \
      --override-input bisca/nixpkgs "git+file://~/nixpkgs?rev=${rev}"
```

With `--override-input` we achieve exactly that: point bisca's `nixpkgs` to our
local repo, and since `crossPkgs` is based on bisca's own `nixpkgs` (the
`crossPkgs = import bisca.inputs.nixpkgs` line), the package will be built with
that revision.

Let's put everything together:

```
$ git bisect start nixpkgs-unstable b40629efe5d6ec48dd1efba650c797ddbd39ace0
Bisecting: 15846 revisions left to test after this (roughly 14 steps)
[3113894db88dad207079a49632efb947f11cf80d] Merge master into staging-nixos

$ git bisect run sh -c '
  nix build ~/nix-config#nixosConfigurations.rpi.config.services.bisca.backend.package \
  --override-input bisca/nixpkgs "git+file://~/nixpkgs?rev=$(git rev-parse HEAD)" \
  --no-link
'
```

now we can go grab a coffee, and once we are back `git bisect` should have found
the first bad revision: after all, we are just building bisca ~14 times, right?

Well, not that fast. With this approach we'll most likely come back to a
nix-daemon busy compiling random things, rather than to a finished bisect.

Why is that? Because we are allowing every single commit in `nixpkgs` to be used
as `nixpkgs` input, and this means we can end up in some revision that produces
derivations that are not cached by Hydra. To see why some commits are cached and
others aren't, a quick (simplified) recap on how branching works in `nixpkgs` is
in order.

### nixpkgs branching model

Problem statement: all changes landing on `master` cause Hydra to rebuild
everything that depends on said changes. This might end up causing a [mass
rebuild](https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md#changes-causing-mass-rebuilds)
(which is bad use of the infra) so commits usually get merged and piled up in
the `staging` branch and then regularly merged into `staging-next`, which is
manually built/tested on Hydra. If there are no major regressions, this gets
merged into `master`.

Here's the same thing as a diagram from the
[CONTRIBUTING](https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md#staging)
doc:

{{ image(path="nixpkgs-branching.png", width=600) }}

The relevant bit for us: Hydra builds and caches (besides manual runs) what
lands on the tip of `master` and `staging-next` (`master` then gets
fast-forwarded into `nixpkgs-unstable` when the build is successful). The
`staging` branch itself is not built on Hydra, and neither are mid-PR commits
inside any of the merges.

So if we land on a mid-PR commit, we'll likely hit cache misses, which could
require rebuilding lots of stuff (including rustc, llvm etc). And that takes
quite a while.

### Optimizing the bisect process

Can we optimize this? Partially yes: we walk only the branch's mainline (merge
commits and commits pushed directly onto `master`, cached by Hydra), avoiding
the inner commits of the branches/PRs that got merged in.

Why _partial_: this keeps us in cached territory while we're following
`master`'s mainline, and even when we peel into a `staging-next -> master` merge
we stay cached (`staging-next` tips are built by Hydra too). But the regression
likely lives in a `staging -> staging-next` merge, and once we peel into that
range we're walking the staging mainline, which Hydra doesn't build. So we'll
have to deal with cache misses _eventually_, just on a much smaller set of
commits (and I'd expect commits within the same `staging` branch to share more
derivations, so fewer cache misses as the bisect narrows down).

Great, how do we do that in practice? git bisect has exactly the right tool for
following the mainline of a branch. From its man:

```
     --first-parent
         Follow only the first parent commit upon seeing a merge commit.

         In detecting regressions introduced through the merging of a branch, the merge commit will be identified as introduction of the bug and its ancestors will be ignored.

         This option is particularly useful in avoiding false positives when a merged branch contained broken or non-buildable commits, but the merge itself was OK.
```

Let's give it another try with:

```
$ git bisect start --first-parent nixpkgs-unstable b40629efe5d6ec48dd1efba650c797ddbd39ace0
```

This time, after a few minutes git bisect is done:

```
$ git bisect log
[..]
# first bad commit: [9cadaf6932b7c926e468f777549d57f04a7212da] staging-next 2026-04-07 (#507470)
```

and without much surprise.. it's a merge commit.

### Peeling off the first layer

As anticipated, the next step is to peel/bisect into the `staging-next ->
master` specific PR and find which `staging -> staging-next` PR introduced the
breakage. We start from the merge commit that git bisect gave us, get its first
parent (in `master`'s mainline, good one) and its second parent
(`staging-next`'s HEAD, bad one), and bisect the mainline commits in that range:

```
$ git bisect start --first-parent 9cadaf6932b7c926e468f777549d57f04a7212da^2 9cadaf6932b7c926e468f777549d57f04a7212da^1
```

without much surprise, this also didn't take long:

```
$ git bisect log
[..]
# first bad commit: [d79f9e22fa7067d6ae209c14c207ec0af3fea5d4] Merge branch 'staging' into staging-next
```

Now unfortunately we move into the painful part: we need to bisect the `staging`
branch, where almost all PRs get merged into, and which is not built on Hydra:

```
$ git bisect start --first-parent d79f9e22fa7067d6ae209c14c207ec0af3fea5d4^2 d79f9e22fa7067d6ae209c14c207ec0af3fea5d4^1
[..]
Bisecting: 181 revisions left to test after this (roughly 8 steps)
```

Roughly 8 commits to test, with all their cache misses. Still an improvement
from the initial 14 commits to test though.

For this last round I had to let `git bisect` run for a few hours, but this time
it gave me an actual commit!

```
$ git bisect log
[..]
# first bad commit: [21ad3e929a5074dec3565eb53d29ed7ad715996e] treewide: Remove continuation escape at end of commands (#497857)
```

The next thing to do was to look into the bad commit, try to revert it on top of
`nixpkgs-unstable` to see if bisca would build with that (it did), and fill a
PR.

Quiz time: what was wrong with the buggy commit? ([solution](https://github.com/NixOS/nixpkgs/pull/519017))

### Closing words

This was fun, and next time something breaks it'll be definitely easier to hunt
down what's causing the breakage, but in the meantime, what happens while my fix
gets reviewed and merged? Do I keep my rpi broken? Of course not, I just point
bisca's nixpkgs to my branch:

```
{
  inputs = {
    # ..
    bisca = {
      url = "git+ssh://git@github.com/jibi/bisca";
      inputs.nixpkgs.url = "github:jibi/nixpkgs/partial-revert-remove-trailing-line-continuations";
    };
```

and everything will build fine.

## The picture

![Braies](braies.jpg)

View of the Croda del Becco (Seekofel) peak of the Dolomites from Lago di Braies (Pragser Wildsee).
