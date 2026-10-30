$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$g='C:\Program Files\Git\cmd\git.exe'
$env:GIT_TERMINAL_PROMPT='0';$env:GCM_INTERACTIVE='Never'
$ctl='E:\Workspaces\_control'
# JiangLanLu: merge the GitHub legacy tip with the canonical split-sync chain.
$jRepo='E:\Workspaces\jianglanlu\repo'
$jGh='https://github.com/tyj1987/jianglanlu.git';$jGl='https://gitlab.52trz.com/52trz/jianglanlu.git'
$jRef='refs/heads/migration/rog-20260923-source-only';$jSync='refs/heads/migration/rog-20260923-synced'
$jGhTip=(@(& $g ls-remote $jGh $jRef)[0] -split '\s+')[0]
$jGlTip=(@(& $g ls-remote $jGl $jRef)[0] -split '\s+')[0]
$jCanonical=(@(& $g ls-remote $jGh $jSync)[0] -split '\s+')[0]
$jCanonicalGl=(@(& $g ls-remote $jGl $jSync)[0] -split '\s+')[0]
if($jCanonical -ne $jCanonicalGl){throw 'JiangLan canonical branch differs'}
& $g -C $jRepo fetch --no-tags $jGh ($jRef+':refs/rog-sync/j-legacy-gh') $jSync
if($LASTEXITCODE -ne 0){throw 'JiangLan GitHub fetch failed'}
& $g -C $jRepo fetch --no-tags $jGl ($jRef+':refs/rog-sync/j-legacy-gl') $jSync
if($LASTEXITCODE -ne 0){throw 'JiangLan GitLab fetch failed'}
& $g -C $jRepo merge-base --is-ancestor $jGlTip $jCanonical
if($LASTEXITCODE -ne 0){throw 'GitLab legacy is not ancestor of canonical'}
$jTree=& $g -C $jRepo rev-parse ($jCanonical+'^{tree}')
$jReview=Get-Content -LiteralPath 'D:\03_Data\ROG-Migration-Audit\20260923-033102\round2\jianglan-current-full-summary.json' -Raw -Encoding UTF8|ConvertFrom-Json
if($jReview.findings -ne 0 -or $jReview.tree -ne $jTree){throw 'JiangLan reviewed tree mismatch'}
$jMerge=& $g -C $jRepo commit-tree $jTree -p $jGhTip -p $jCanonical -m 'chore: converge legacy source-only refs'
if($LASTEXITCODE -ne 0){throw 'JiangLan merge commit failed'}
& $g -C $jRepo push $jGh ($jMerge+':'+$jRef);if($LASTEXITCODE -ne 0){throw 'JiangLan GitHub push failed'}
& $g -C $jRepo push $jGl ($jMerge+':'+$jRef);if($LASTEXITCODE -ne 0){throw 'JiangLan GitLab push failed'}
# 52trz: copy the GitLab bootstrap legacy ref to GitHub; no rewrite.
$tRepo='E:\Workspaces\52trz-platform\repo'
$tGh='https://github.com/tyj1987/52trz-platform.git';$tGl='https://gitlab.52trz.com/52trz/52trz-platform.git'
$tRef='refs/heads/migration/rog-20260923-source-only'
$tGlLine=@(& $g ls-remote $tGl $tRef);if($LASTEXITCODE -ne 0 -or $tGlLine.Count -ne 1){throw '52trz bootstrap ref unavailable'}
$tBase=($tGlLine[0] -split '\s+')[0]
$tGhLine=@(& $g ls-remote $tGh $tRef)
if($tGhLine.Count -eq 0){
 & $g -C $tRepo fetch --no-tags $tGl ($tRef+':refs/rog-sync/52-bootstrap')
 if($LASTEXITCODE -ne 0){throw '52trz bootstrap fetch failed'}
 & $g -C $tRepo push $tGh ($tBase+':'+$tRef)
 if($LASTEXITCODE -ne 0){throw '52trz bootstrap GitHub push failed'}
}elseif((($tGhLine[0] -split '\s+')[0]) -ne $tBase){throw '52trz GitHub legacy ref exists with different tip'}
# Verify both repositories now have identical head maps.
function Get-Heads([string]$url){$m=@{};foreach($line in @(& $g ls-remote --heads $url)){$p=$line -split '\s+',2;if($p.Count -eq 2){$m[$p[1]]=$p[0]}};return $m}
$jA=Get-Heads $jGh;$jB=Get-Heads $jGl;$tA=Get-Heads $tGh;$tB=Get-Heads $tGl
function Diff-Count($a,$b){$keys=@($a.Keys+$b.Keys|Sort-Object -Unique);return @($keys|Where-Object {$a[$_] -ne $b[$_]}).Count}
$r=[ordered]@{
 jianglan=@{merge_commit=$jMerge;github_heads=$jA.Count;gitlab_heads=$jB.Count;differences=(Diff-Count $jA $jB)};
 '52trz-platform'=@{bootstrap_tip=$tBase;github_heads=$tA.Count;gitlab_heads=$tB.Count;differences=(Diff-Count $tA $tB)};
 observed_utc=(Get-Date).ToUniversalTime().ToString('o')
}
$r|ConvertTo-Json -Depth 5|Set-Content -LiteralPath ($ctl+'\legacy-ref-convergence-20260923.json') -Encoding UTF8
$r|ConvertTo-Json -Depth 5 -Compress
