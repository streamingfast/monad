# StreamingFast Changelog

Changelog for the StreamingFast fork of [monad](https://github.com/category-labs/monad), the
Monad execution client with the block system call events the Firehose tracer reads. It tracks
only the fork's own releases (the `*-fh*` tags); upstream changes are covered by the
[upstream releases](https://github.com/category-labs/monad/releases).

## v0.16.6-fh3.1

* Bumped to [v0.16.6](https://github.com/category-labs/monad/releases/tag/v0.16.6).
* Add `ACTIVATIONS.md`, listing every Monad revision and its effect on the Firehose block.
* Live execution now requires a page-encoded database (`monad-mpt --upgrade` is removed upstream); see the [upgrade instructions](https://docs.monad.xyz/node-ops/upgrade-instructions/v0.16.6).
