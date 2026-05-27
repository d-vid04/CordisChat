Drop `icon.png` (a 512×512 transparent PNG) in this directory before
`cargo tauri build`. For `cargo tauri dev` it's optional.

Easiest workflow: take any source PNG/SVG and run

    cargo tauri icon path/to/source.png

from the project root — Tauri generates the full set of platform-
specific icons (.icns, .ico, the various PNG sizes) into this dir.
