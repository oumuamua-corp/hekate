# Contributing

Hekate does not accept external code contributions.

## Why

Hekate is dual-licensed: AGPL-3.0-only for open use, and a separate commercial license from
Oumuamua Labs. Selling that commercial license, and building the proprietary prover shared library
on top of these crates, both require Oumuamua Labs to hold the rights to every line in the tree.
A patch offered under the AGPL alone can be used for neither, and merging one would permanently
remove that code from both.

There is no contributor license agreement in place. Until there is, pull requests carrying code
cannot be merged, regardless of quality.

## What is welcome

- Bug reports, with a reproduction.
- Performance measurements that contradict the numbers in the README.
- Documentation errors.

Open an issue at <https://github.com/oumuamua-labs/hekate/issues>.

## Security

Do not open a public issue for a soundness break, a Fiat-Shamir binding defect, or anything that
leaks a witness. Mail <info@oumuamua.dev>.
