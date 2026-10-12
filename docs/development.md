# Development

## Environment

The existing project files reference:

- Visual Studio 2022 with Desktop development with C++.
- MSVC v143 for the loader.
- A Windows SDK and compatible Windows Driver Kit installation.
- The `WindowsKernelModeDriver10.0` toolset for the driver.
- The Visual Studio DIA SDK, including its x64 library directory.

The projects use the compiler's latest C++ language mode rather than a fixed language-standard version. These requirements describe the project configuration; they are not a verified compatibility matrix.

## Visual Studio organization

Open `kernel-mapper.sln` to inspect both projects. The solution exposes Debug and Release x64 configurations. The driver's separate ARM64 configurations do not imply that the loader or complete solution supports ARM64.

The loader uses project-relative include paths. Its existing post-build event copies `msdia140.dll` from the DIA SDK when that file exists. The driver retains its existing entry-point, packaging and signing settings.

## Outputs

The configured x64 output paths are:

```text
build/output/debug/loader/
build/output/debug/driver/
build/output/release/loader/
build/output/release/driver/
```

Intermediate files are configured under `build/intermediate/`. Do not commit binaries, signing material, Visual Studio caches or machine-specific project settings.

## Verification boundaries

For structural changes, review project references, source paths, solution configurations and `git diff --check`. Record any actual compilation results with the toolchain and configuration used; do not describe static checks as a successful build.

No automated test suite is currently provided. Compiling a kernel research project does not validate its runtime safety. Runtime investigation belongs in a separate, explicitly authorized laboratory with recovery provisions and no valuable data. This document does not provide instructions for loading payloads or changing system protections.
