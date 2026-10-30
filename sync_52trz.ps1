$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$g='C:\Program Files\Git\cmd\git.exe'
$repo='E:\Workspaces\52trz-platform\repo'
$ctl='E:\Workspaces\_control'
$gh='https://github.com/tyj1987/52trz-platform.git'
$gl='https://gitlab.52trz.com/52trz/52trz-platform.git'
$branch='migration/rog-20260923-synced'
$ref='refs/heads/'+$branch
$tree='586530bfa86262d2143dc36a0d9c8be6083c6994'
$review=Get-Content -LiteralPath ($ctl+'\52trz-reviewed-rescan-summary.json') -Raw -Encoding UTF8|ConvertFrom-Json
if(-not $review.safe_to_publish_tree -or $review.tree -ne $tree -or $review.remaining_findings -ne 0){throw 'Reviewed tree does not match'}
$headBefore=& $g -C $repo rev-parse HEAD
$indexPath=& $g -C $repo rev-parse --path-format=absolute --git-path index
$indexHashBefore=(Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
if(@(& $g ls-remote $gh $ref).Count -ne 0){throw 'GitHub sync branch already exists'}
if(@(& $g ls-remote $gl $ref).Count -ne 0){throw 'GitLab sync branch already exists'}
$baseLine=@(& $g ls-remote $gl refs/heads/migration/rog-20260923-source-only)
if($LASTEXITCODE -ne 0 -or $baseLine.Count -ne 1){throw 'GitLab bootstrap branch unavailable'}
$base=($baseLine[0] -split '\s+')[0]
& $g -C $repo fetch --no-tags $gl ('refs/heads/migration/rog-20260923-source-only:refs/rog-sync/52trz-base')
if($LASTEXITCODE -ne 0){throw 'Fetch bootstrap failed'}
$commit=& $g -C $repo commit-tree $tree -p $base -m 'chore: publish reviewed ROG source snapshot'
if($LASTEXITCODE -ne 0){throw 'commit-tree failed'}
& $g -C $repo update-ref $ref $commit
if($LASTEXITCODE -ne 0){throw 'local sync ref failed'}
& $g -C $repo push $gl ($commit+':'+$ref)
if($LASTEXITCODE -ne 0){throw 'GitLab push failed'}
& $g -C $repo push $gh ($commit+':'+$ref)
if($LASTEXITCODE -ne 0){throw 'GitHub push failed'}
if(-not((& $g -C $repo remote) -contains 'origin')){& $g -C $repo remote add origin $gh}
if(-not((& $g -C $repo remote) -contains 'gitlab')){& $g -C $repo remote add gitlab $gl}
$headAfter=& $g -C $repo rev-parse HEAD
$indexHashAfter=(Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash
$ghTip=(@(& $g ls-remote $gh $ref)[0] -split '\s+')[0]
$glTip=(@(& $g ls-remote $gl $ref)[0] -split '\s+')[0]
$treeAfter=& $g -C $repo rev-parse ($commit+'^{tree}')
$result=[ordered]@{
 project='52trz-platform';canonical_sync_branch=$branch;reviewed_tree=$tree;commit=$commit;
 github_tip=$ghTip;gitlab_tip=$glTip;equal=($commit -eq $ghTip -and $commit -eq $glTip);
 tree_equal=($treeAfter -eq $tree);head_unchanged=($headBefore -eq $headAfter);index_unchanged=($indexHashBefore -eq $indexHashAfter);
 reviewed_false_positives=$review.reviewed_findings;remaining_findings=$review.remaining_findings;
 observed_utc=(Get-Date).ToUniversalTime().ToString('o')
}
$result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath ($ctl+'\52trz-dual-remote-sync-20260923.json') -Encoding UTF8
$result|ConvertTo-Json -Compress
