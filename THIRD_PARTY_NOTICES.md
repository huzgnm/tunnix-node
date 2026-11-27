# Third-party notices

## shoes

TunnixNode's protocol core (`crates/core`) is a modified fork of shoes,
https://github.com/cfal/shoes, at commit `5941f7d9610674ae6750a020521dc8bf8aba15c8`.
TunnixNode changes are kept in `crates/core/src/tunnix/` and marked `// tunnix:` in upstream files.

```
Copyright (c) 2021-2023 Alex Lau <github@alau.ca>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Rust crates

Other dependencies are listed in `Cargo.lock` and are used under their own
licenses (mostly MIT and/or Apache-2.0). Run `cargo about` or `cargo license` for the full list.
