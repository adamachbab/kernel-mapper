# Project layout

## Solution

`kernel-mapper.sln` references the `loader` and `driver` projects. The solution exposes Debug and Release x64 configurations. Project GUIDs and output names are kept independent of the repository name.

## Loader

| Location | Responsibility |
| --- | --- |
| `loader/src/main.cpp` | Application entry point |
| `loader/src/common/` | Shared includes, types and console logging |
| `loader/src/symbols/` | Symbol information and export handling |
| `loader/src/driver/` | Driver-related interfaces and resources |
| `loader/src/memory/` | Memory-related research components |
| `loader/src/memory/map/` | Image-handling components and entry contract |
| `loader/third_party/` | Vendored dependencies |

## Reference driver

`driver/src/main.cpp` contains the reference entry implementation. `driver/driver.inf` contains installation metadata, and `driver/driver.vcxproj` declares the WDK build configuration. Moving the source into `src/` does not change its entry contract or implementation.

## Documentation

- `README.md`: project overview and navigation.
- `docs/development.md`: development environment and configuration boundaries.
- `docs/loader.png`: illustrative console screenshot.
- `CONTRIBUTING.md`: contribution expectations.
- `SECURITY.md`: reporting and laboratory safety guidance.

## Generated files

The x64 projects configure output directories under `build/output/<configuration>/<project>/` and intermediate directories under `build/intermediate/<configuration>/<project>/`. Visual Studio caches, build products and local user settings are ignored by Git.
