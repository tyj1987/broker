$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$g='C:\Program Files\Git\cmd\git.exe'
$repo='E:\Workspaces\jianglanlu\repo'
$ctl='E:\Workspaces\_control'
$gh='https://github.com/tyj1987/jianglanlu.git'
$gl='https://gitlab.52trz.com/52trz/jianglanlu.git'
$branch='migration/rog-20260923-synced'
$ref='refs/heads/'+$branch
$sourceCommit=& $g -C $repo rev-parse refs/heads/migration/rog-20260923-source-only
$sourceTree=& $g -C $repo rev-parse ($sourceCommit+'^{tree}')
$scan=Get-Content -LiteralPath 'D:\03_Data\ROG-Migration-Audit\20260923-033102\round2\jianglan-current-full-summary.json' -Raw -Encoding UTF8|ConvertFrom-Json
if($scan.rc -ne 0 -or $scan.findings -ne 0 -or $scan.tree -ne $sourceTree){throw 'Previously verified source tree no longer matches'}
$oldGl=@(& $g ls-remote $gl refs/heads/migration/rog-20260923-source-only)
if($LASTEXITCODE -ne 0 -or $oldGl.Count -ne 1){throw 'GitLab bootstrap source branch unavailable'}
$base=($oldGl[0] -split '\s+')[0]
if(@(& $g ls-remote $gh $ref).Count -ne 0){throw 'Target branch already exists on GitHub'}
if(@(& $g ls-remote $gl $ref).Count -ne 0){throw 'Target branch already exists on GitLab'}
& $g -C $repo fetch --no-tags $gl ('refs/heads/migration/rog-20260923-source-only:refs/rog-sync/v2-base')
if($LASTEXITCODE -ne 0){throw 'Cannot fetch GitLab base'}
$ls=@(& $g -C $repo ls-tree -r -l $sourceTree)
$files=@()
foreach($line in $ls){
 if($line -match '^(\d+)\s+blob\s+([0-9a-f]+)\s+(\d+)\s+(.+)$'){
   $files += [pscustomobject]@{mode=$matches[1];sha=$matches[2];bytes=[int64]$matches[3];path=$matches[4]}
 }
}
if($files.Count -eq 0){throw 'No source files'}
$limit=20MB
$batches=@();$current=@();$size=0L
foreach($f in $files){
 if($current.Count -gt 0 -and ($size+$f.bytes) -gt $limit){$batches+=,@($current);$current=@();$size=0}
 $current+=$f;$size+=$f.bytes
}
if($current.Count -gt 0){$batches+=,@($current)}
$idx=$ctl+'\jianglan-split-sync.index'
if(Test-Path -LiteralPath $idx){Remove-Item -LiteralPath $idx -Force}
$env:GIT_INDEX_FILE=$idx
$parent=$base;$commits=@()
try{
 & $g -C $repo read-tree --empty
 if($LASTEXITCODE -ne 0){throw 'read-tree empty failed'}
 for($i=0;$i -lt $batches.Count;$i++){
   foreach($f in $batches[$i]){
     & $g -C $repo update-index --add --cacheinfo ($f.mode+','+$f.sha+','+$f.path)
     if($LASTEXITCODE -ne 0){throw ('update-index failed for '+$f.path)}
   }
   $tree=& $g -C $repo write-tree
   if($LASTEXITCODE -ne 0){throw 'write-tree failed'}
   $commit=& $g -C $repo commit-tree $tree -p $parent -m ('chore: ROG source sync batch '+($i+1)+'/'+$batches.Count)
   if($LASTEXITCODE -ne 0){throw 'commit-tree failed'}
   & $g -C $repo update-ref $ref $commit
   if($LASTEXITCODE -ne 0){throw 'update-ref failed'}
   & $g -C $repo push $gl ($commit+':'+$ref)
   if($LASTEXITCODE -ne 0){throw ('GitLab batch push failed at '+($i+1))}
   & $g -C $repo push $gh ($commit+':'+$ref)
   if($LASTEXITCODE -ne 0){throw ('GitHub batch push failed at '+($i+1))}
   $commits += [pscustomobject]@{batch=$i+1;files=$batches[$i].Count;commit=$commit;tree=$tree;estimated_blob_bytes=($batches[$i]|Measure-Object bytes -Sum).Sum}
   $parent=$commit
 }
} finally {Remove-Item Env:GIT_INDEX_FILE -ErrorAction SilentlyContinue}
$finalTree=& $g -C $repo rev-parse ($parent+'^{tree}')
if($finalTree -ne $sourceTree){throw 'Final split-sync tree does not equal verified source tree'}
$ghTip=(@(& $g ls-remote $gh $ref)[0] -split '\s+')[0]
$glTip=(@(& $g ls-remote $gl $ref)[0] -split '\s+')[0]
if(-not((& $g -C $repo remote) -contains 'origin')){& $g -C $repo remote add origin $gh}
if(-not((& $g -C $repo remote) -contains 'gitlab')){& $g -C $repo remote add gitlab $gl}
$result=[ordered]@{project='jianglanlu';canonical_sync_branch=$branch;source_tree=$sourceTree;verified_scan_findings=0;files=$files.Count;blob_bytes=($files|Measure-Object bytes -Sum).Sum;batches=$commits;final_commit=$parent;github_tip=$ghTip;gitlab_tip=$glTip;equal=($parent -eq $ghTip -and $parent -eq $glTip);legacy_branch_divergence_retained=$true;observed_utc=(Get-Date).ToUniversalTime().ToString('o')}
$result|ConvertTo-Json -Depth 7|Set-Content -LiteralPath ($ctl+'\jianglan-split-dual-sync-20260923.json') -Encoding UTF8
$result|ConvertTo-Json -Depth 4 -Compress
