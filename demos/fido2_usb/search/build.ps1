# Builds fido_search.exe with a bare rustc: no crates, no cargo, no network.
$ErrorActionPreference = "Stop"
$env:PATH = "$env:PATH;$env:USERPROFILE\.cargo\bin"
rustc --edition 2021 -O -C opt-level=3 -C target-cpu=native -C codegen-units=1 -C panic=abort `
      src\main.rs -o fido_search.exe
# $ErrorActionPreference does not apply to a native exit code, so check it: without
# this the script printed "built" over a failed rustc and left the previous exe in
# place, which is the worst possible combination.
if ($LASTEXITCODE -ne 0) { Write-Error "rustc failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }
Write-Host "built fido_search.exe"
