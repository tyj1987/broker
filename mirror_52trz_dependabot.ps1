$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$g='C:\Program Files\Git\cmd\git.exe'
$repo='E:\Workspaces\52trz-platform\repo'
$gh='https://github.com/tyj1987/52trz-platform.git'
$gl='https://gitlab.52trz.com/52trz/52trz-platform.git'
$env:GIT_TERMINAL_PROMPT='0';$env:GCM_INTERACTIVE='Never'
$ghLines=@(& $g ls-remote --heads $gh 'refs/heads/dependabot/*')
if($LASTEXITCODE -ne 0){throw 'GitHub dependabot listing failed'}
$glLines=@(& $g ls-remote --heads $gl 'refs/heads/dependabot/*')
if($LASTEXITCODE -ne 0){throw 'GitLab dependabot listing failed'}
$glMap=@{};foreach($line in $glLines){$p=$line -split '\s+',2;if($p.Count -eq 2){$glMap[$p[1]]=$p[0]}}
$mirrored=@()
foreach($line in $ghLines){
 $p=$line -split '\s+',2;if($p.Count -ne 2){continue}
 $sha=$p[0];$ref=$p[1]
 if($glMap.ContainsKey($ref)){
   if($glMap[$ref] -ne $sha){throw ('Existing GitLab dependabot ref differs: '+$ref)}
   continue
 }
 $tmp='refs/rog-sync/dependabot/'+([IO.Path]::GetFileName($ref))+'-'+$sha.Substring(0,8)
 & $g -C $repo fetch --no-tags $gh ($ref+':'+$tmp)
 if($LASTEXITCODE -ne 0){throw ('Fetch failed '+$ref)}
 & $g -C $repo push $gl ($sha+':'+$ref)
 if($LASTEXITCODE -ne 0){throw ('Push failed '+$ref)}
 $mirrored += [pscustomobject]@{ref=$ref;sha=$sha}
}
$after=@(& $g ls-remote --heads $gl 'refs/heads/dependabot/*')
$afterMap=@{};foreach($line in $after){$p=$line -split '\s+',2;if($p.Count -eq 2){$afterMap[$p[1]]=$p[0]}}
$ok=$true;foreach($line in $ghLines){$p=$line -split '\s+',2;if(-not $afterMap.ContainsKey($p[1]) -or $afterMap[$p[1]] -ne $p[0]){$ok=$false}}
$r=[ordered]@{project='52trz-platform';mirrored=$mirrored;github_dependabot_count=$ghLines.Count;gitlab_dependabot_count=$after.Count;all_dependabot_equal=$ok;legacy_source_only_divergence_retained=$true;canonical_branch='migration/rog-20260923-synced';observed_utc=(Get-Date).ToUniversalTime().ToString('o')}
$r|ConvertTo-Json -Depth 5|Set-Content -LiteralPath 'E:\Workspaces\_control\52trz-dependabot-mirror-20260923.json' -Encoding UTF8
$r|ConvertTo-Json -Compress
