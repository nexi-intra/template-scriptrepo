$toolRoot = Join-Path $PSScriptRoot ".." "tools" 
if (-not (Test-Path $toolRoot)) {
  New-Item -ItemType Directory -Path $toolRoot 
}

try {
  Set-Location $toolRoot
  $mateRoot = Join-Path $toolRoot "koksmat-mate"
  if (-not (Test-Path $mateRoot)) {
    git clone "https://github.com/koksmat-com/koksmat-mate.git" 
  }
  $mateRoot = Resolve-Path $mateRoot 
  set-location $mateRoot
  
  if (-not (Test-Path (join-path $mateRoot ".next"))) {
    pnpm install
    pnpm run build  
  }

  
  pnpm run dev

  
}
catch {
  write-host "Error: $_" -ForegroundColor Red
  
  <#Do this if a terminating exception happens#>
}
finally {
  Pop-Location
  <#Do this after the try block regardless of whether an exception occurred or not#>
}
