$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$g='C:\Program Files\Git\cmd\git.exe'
$leaks='D:\03_Data\ROG-Migration-Audit\20260923-033102\tools\gitleaks.exe'
$config='D:\03_Data\ROG-Migration-Audit\20260923-033102\gitleaks-default.toml'
$repo='E:\Workspaces\jianglanlu\repo'
$ctl='E:\Workspaces\_control'
$branch='migration/rog-20260923-source-only'
$ref='refs/heads/'+$branch
$gh='https://github.com/tyj1987/jianglanlu.git'
$gl='https://gitlab.52trz.com/52trz/jianglanlu.git'
$env:GIT_TERMINAL_PROMPT='0'; $env:GCM_INTERACTIVE='Never'
$headBefore=& $g -C $repo rev-parse HEAD
$indexPath=& $g -C $repo rev-parse --path-format=absolute --git-path index
$indexHashBefore=(Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
$ghLine=@(& $g ls-remote $gh $ref); if($LASTEXITCODE -ne 0 -or $ghLine.Count -ne 1){throw 'GitHub source-only branch unavailable'}
$glLine=@(& $g ls-remote $gl $ref); if($LASTEXITCODE -ne 0 -or $glLine.Count -ne 1){throw 'GitLab source-only branch unavailable'}
$ghTip=($ghLine[0] -split '\s+')[0]; $glTip=($glLine[0] -split '\s+')[0]
& $g -C $repo fetch --no-tags $gh ($ref+':refs/rog-sync/jianglan-github'); if($LASTEXITCODE -ne 0){throw 'GitHub fetch failed'}
& $g -C $repo fetch --no-tags $gl ($ref+':refs/rog-sync/jianglan-gitlab'); if($LASTEXITCODE -ne 0){throw 'GitLab fetch failed'}
$idx=$ctl+'\jianglan-sync.index'; if(Test-Path -LiteralPath $idx){Remove-Item -LiteralPath $idx -Force}
$env:GIT_INDEX_FILE=$idx
try{
 & $g -C $repo read-tree HEAD; if($LASTEXITCODE -ne 0){throw 'read-tree failed'}
 & $g -C $repo add -A -- .; if($LASTEXITCODE -ne 0){throw 'temporary add failed'}
 & $leaks git $repo --pre-commit --staged --config $config --gitleaks-ignore-path $ctl --ignore-gitleaks-allow --redact=100 --no-banner --no-color --report-format json --report-path ($ctl+'\jianglan-sync-gitleaks.json') --timeout 120
 if($LASTEXITCODE -ne 0){throw 'Secret scan blocked snapshot'}
 $tree=& $g -C $repo write-tree; if($LASTEXITCODE -ne 0){throw 'write-tree failed'}
 $parents=@($ghTip,$glTip|Select-Object -Unique)
 $args=@('-C',$repo,'commit-tree',$tree)
 foreach($p in $parents){$args+=@('-p',$p)}
 $args+=@('-m','chore: converge ROG workspace snapshot across remotes')
 $commit=& $g @args; if($LASTEXITCODE -ne 0){throw 'commit-tree failed'}
} finally {Remove-Item Env:GIT_INDEX_FILE -ErrorAction SilentlyContinue}
$headAfter=& $g -C $repo rev-parse HEAD
$indexHashAfter=(Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
if($headAfter -ne $headBefore){throw 'Current HEAD changed'}
if($indexHashAfter -ne $indexHashBefore){throw 'Real index changed'}
& $g -C $repo update-ref ('refs/heads/'+$branch) $commit
if($LASTEXITCODE -ne 0){throw 'local sync ref failed'}
& $g -C $repo push $gh ($commit+':'+$ref); if($LASTEXITCODE -ne 0){throw 'GitHub fast-forward push failed'}
& $g -C $repo push $gl ($commit+':'+$ref); if($LASTEXITCODE -ne 0){throw 'GitLab fast-forward push failed'}
if(-not((& $g -C $repo remote) -contains 'origin')){& $g -C $repo remote add origin $gh}
if(-not((& $g -C $repo remote) -contains 'gitlab')){& $g -C $repo remote add gitlab $gl}
$ghAfter=(@(& $g ls-remote $gh $ref)[0] -split '\s+')[0]
$glAfter=(@(& $g ls-remote $gl $ref)[0] -split '\s+')[0]
$result=[ordered]@{project='jianglanlu';branch=$branch;old_github=$ghTip;old_gitlab=$glTip;converged_commit=$commit;github_after=$ghAfter;gitlab_after=$glAfter;equal=($commit -eq $ghAfter -and $commit -eq $glAfter);head_unchanged=($headBefore -eq $headAfter);index_unchanged=($indexHashBefore -eq $indexHashAfter);secret_scan_rc=0;observed_utc=(Get-Date).ToUniversalTime().ToString('o')}
$result|ConvertTo-Json -Depth 4|Set-Content -LiteralPath ($ctl+'\jianglan-dual-remote-sync-20260923.json') -Encoding UTF8
$result|ConvertTo-Json -Compress
