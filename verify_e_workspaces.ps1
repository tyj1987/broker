$ErrorActionPreference='Continue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$g='C:\Program Files\Git\cmd\git.exe'
$ctl='E:\Workspaces\_control'
$items=@(
 @('broker','E:\Workspaces\broker\repo'),
 @('chatlink-runtime','E:\Workspaces\chatlink\repositories\runtime-stability'),
 @('chatlink-commercial','E:\Workspaces\chatlink\repo'),
 @('woai-store','E:\Workspaces\woai-download\worktrees\woai-store-validation-20260920'),
 @('woai-commerce','E:\Workspaces\woai-download\repo'),
 @('lumia950-linux-desktop','E:\Workspaces\lumia950-linux-desktop\repo'),
 @('moxiang','E:\Workspaces\moxiang\repo'),
 @('moxian-terminal','E:\Workspaces\moxian-terminal\repo'),
 @('jianglanlu','E:\Workspaces\jianglanlu\repo'),
 @('52trz-platform','E:\Workspaces\52trz-platform\repo'),
 @('infra','E:\Workspaces\infra\repo'),
 @('billiards-web','E:\Workspaces\billiards-web\repo'),
 @('open-webui','E:\Workspaces\open-webui\repo'),
 @('textbook-parser','E:\Workspaces\textbook-parser\repo'),
 @('qinglan-art','E:\Workspaces\qinglan-art\assets'),
 @('mercedes-e300l','E:\Workspaces\mercedes-e300l\assets')
)
$rows=@()
foreach($t in $items){
 $p=$t[1]
 if(-not(Test-Path -LiteralPath $p)){ $rows += [pscustomobject]@{project=$t[0];path=$p;exists=$false}; continue }
 $it=Get-Item -LiteralPath $p -Force
 $head=& $g -C $p rev-parse --verify HEAD 2>$null; $hr=$LASTEXITCODE
 $branch=& $g -C $p branch --show-current 2>$null
 $status=@(& $g --no-optional-locks -c core.fsmonitor=false -C $p status --porcelain=v1 --untracked-files=normal 2>$null); $sr=$LASTEXITCODE
 $common=& $g -C $p rev-parse --path-format=absolute --git-common-dir 2>$null; $cr=$LASTEXITCODE
 $notice=(Join-Path (Split-Path $p -Parent) 'WORKSPACE_NOTICE.md')
 $rows += [pscustomobject]@{
   project=$t[0]; path=$p; exists=$true; link_type=$it.LinkType; link_target=$it.Target;
   head_rc=$hr; head=$head; branch=$branch; status_rc=$sr; dirty_records=$status.Count;
   common_git_dir=if($cr -eq 0){$common}else{$null};
   common_git_dir_on_E=if($cr -eq 0){$common -like 'E:*'}else{$null};
   notice_exists=(Test-Path -LiteralPath $notice)
 }
}
$old=@(
 'C:\moxiang','C:\Users\Administrator\plugins\desktop-link-runtime-stability',
 'C:\Users\Administrator\source\repos\woai-download','C:\Users\Administrator\source\repos\lumia950-linux-desktop',
 'C:\Users\Administrator\source\JiangLanLu','D:\Study\PVE','D:\02_Dev\Projects\Study\MoxianTerminal','E:\新建文件夹'
)
$links=@()
foreach($p in $old){
 if(Test-Path -LiteralPath $p){$x=Get-Item -LiteralPath $p -Force;$links += [pscustomobject]@{path=$p;link_type=$x.LinkType;target=$x.Target;exists=$true}}
 else {$links += [pscustomobject]@{path=$p;exists=$false}}
}
$pub=@('E:\Workspaces\AGENTS.md','C:\CodexData\AGENTS.md','E:\Workspaces\WORKSPACE_REGISTRY.json','E:\Workspaces\MEMORY.json','E:\Workspaces\WORKSPACE-MIGRATION-20260923.md')
$files=@()
foreach($p in $pub){if(Test-Path -LiteralPath $p){$files += [pscustomobject]@{path=$p;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash;bytes=(Get-Item -LiteralPath $p).Length;mtime=(Get-Item -LiteralPath $p).LastWriteTimeUtc}}}
$db=& 'C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE' -S . -E -W -s '|' -Q "SET NOCOUNT ON; SELECT DB_NAME(mf.database_id) database_name, mf.physical_name, d.state_desc FROM sys.master_files mf JOIN sys.databases d ON mf.database_id=d.database_id WHERE DB_NAME(mf.database_id) IN ('mhcmember','mhgame','mhlog','mhcnews') ORDER BY database_name, physical_name;" 2>&1
$result=[ordered]@{
 device='ROG';observed_utc=(Get-Date).ToUniversalTime().ToString('o');projects=$rows;old_paths=$links;
 publication_files=$files;databases=$db;
 disks=@(Get-CimInstance Win32_LogicalDisk|Where-Object {$_.DriveType -eq 3}|Select-Object DeviceID,Size,FreeSpace)
}
$out=$ctl+'\verification-snapshot-20260923-0931.json'
$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $out -Encoding UTF8
Write-Output ('SAVED='+$out)
[pscustomobject]@{projects=$rows.Count;missing_projects=@($rows|Where-Object {-not $_.exists}).Count;publication_files=$files.Count;old_paths=$links;disks=$result.disks}|ConvertTo-Json -Depth 5 -Compress
