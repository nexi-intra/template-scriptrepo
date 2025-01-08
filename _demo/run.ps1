<#---
title: Demonstrate a script
---


This script is getting called by a workflow action. 
#>
$root = [System.IO.Path]::GetFullPath(( join-path $PSScriptRoot ..)) 

. "$root/.koksmat/pwsh/check-env.ps1" "HElLO"



try {
  write-host "Value of HElLO is " -NoNewline
  write-host $env:HElLO -ForegroundColor Yellow
  
  
}
catch {
  write-host "Error: $_" -ForegroundColor:Red
  
}

