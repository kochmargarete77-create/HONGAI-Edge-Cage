[CmdletBinding()]
param([switch]$UISmokeTest,[switch]$Settings,[switch]$DailyLaunchSmokeTest)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Desktop'){$env:PSModulePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')+';'+(Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')}
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$runtime=$PSScriptRoot
$installation=Get-Content -LiteralPath (Join-Path $runtime 'installation.json') -Raw -Encoding UTF8|ConvertFrom-Json
$data=[string]$installation.dataRoot
$null=New-Item -ItemType Directory -Path (Join-Path $data '.tmp') -Force
$env:TEMP=Join-Path $data '.tmp';$env:TMP=$env:TEMP
if($DailyLaunchSmokeTest -and ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows')){throw 'DAILY_LAUNCH_SMOKE_REQUIRES_DISPOSABLE_CI'}
$form=[Windows.Forms.Form]::new();$form.Text='HONG AI CAGE · 桌面隔离工作台';$form.Size=[Drawing.Size]::new(720,470);$form.StartPosition='CenterScreen';$form.BackColor=[Drawing.Color]::FromArgb(249,249,250);$form.Font=[Drawing.Font]::new('Microsoft YaHei UI',10);$form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false
$title=[Windows.Forms.Label]::new();$title.Text='HONG AI / CAGE';$title.Font=[Drawing.Font]::new('Microsoft YaHei UI',24,[Drawing.FontStyle]::Bold);$title.ForeColor=[Drawing.Color]::FromArgb(185,26,42);$title.SetBounds(28,22,630,45);$form.Controls.Add($title)
$subtitle=[Windows.Forms.Label]::new();$subtitle.Text='官方桌面程序 · 独立登录环境 · 工作文件夹授权';$subtitle.ForeColor=[Drawing.Color]::DimGray;$subtitle.SetBounds(30,77,650,27);$form.Controls.Add($subtitle)
$import=[Windows.Forms.Button]::new();$import.Text='选择第一步交接文件';$import.SetBounds(30,120,190,36);$form.Controls.Add($import)
$fileLabel=[Windows.Forms.Label]::new();$fileLabel.SetBounds(238,127,440,25);$fileLabel.Text='首次使用需要导入；之后会自动核验并沿用。';$form.Controls.Add($fileLabel)
$folder=[Windows.Forms.Button]::new();$folder.Text='选择工作文件夹';$folder.SetBounds(30,174,190,36);$form.Controls.Add($folder)
$folderLabel=[Windows.Forms.Label]::new();$folderLabel.SetBounds(238,181,440,27);$folderLabel.AutoEllipsis=$true;$folderLabel.Text='未选择';$form.Controls.Add($folderLabel)
$start=[Windows.Forms.Button]::new();$start.Text='启动 Claude 桌面版';$start.BackColor=[Drawing.Color]::FromArgb(185,26,42);$start.ForeColor=[Drawing.Color]::White;$start.FlatStyle='Flat';$start.SetBounds(30,242,224,43);$form.Controls.Add($start)
$stop=[Windows.Forms.Button]::new();$stop.Text='停止隔离会话';$stop.SetBounds(271,242,180,43);$stop.Enabled=$false;$form.Controls.Add($stop)
$status=[Windows.Forms.Label]::new();$status.SetBounds(30,308,650,58);$status.Text='请保持 Clash 和远控运行。此工作台不修改 Wi-Fi、TUN、系统 DNS 或路由。';$form.Controls.Add($status)
$note=[Windows.Forms.Label]::new();$note.SetBounds(30,377,650,40);$note.ForeColor=[Drawing.Color]::DimGray;$note.Font=[Drawing.Font]::new('Microsoft YaHei UI',9);$note.Text='本地 MCP 与文件工具在专用隔离环境中运行。Cowork 虚拟机和系统级集成暂不启用。';$form.Controls.Add($note)
$script:chosenHandoff=$null;$script:chosenWorkspace=$null;$script:worker=$null;$script:stopSignal=$null
$script:userExit=$false
$script:dailyObserved=$false
if(Test-Path -LiteralPath (Join-Path $data 'enrolled-handoff.json')){$fileLabel.Text='已保存交接配置；启动时重新核对最终出口。'}
if(Test-Path -LiteralPath (Join-Path $data 'workspace.json')){try{$saved=Get-Content (Join-Path $data 'workspace.json') -Raw -Encoding UTF8|ConvertFrom-Json;$script:chosenWorkspace=[string]$saved.workspace;$folderLabel.Text=$script:chosenWorkspace}catch{}}
$import.Add_Click({$dialog=[Windows.Forms.OpenFileDialog]::new();$dialog.Filter='Clash交接文件|clash-handoff.json|JSON|*.json';if($dialog.ShowDialog() -eq 'OK'){$script:chosenHandoff=$dialog.FileName;$fileLabel.Text=[IO.Path]::GetFileName($dialog.FileName)}})
$folder.Add_Click({$dialog=[Windows.Forms.FolderBrowserDialog]::new();$dialog.Description='只选择需要交给 Claude 使用的具体项目文件夹';if($dialog.ShowDialog() -eq 'OK'){$script:chosenWorkspace=$dialog.SelectedPath;$folderLabel.Text=$dialog.SelectedPath}})
function Stop-OwnSession {if($script:stopSignal){[IO.File]::WriteAllText($script:stopSignal,'stop',[Text.UTF8Encoding]::new($false))};$status.Text='正在关闭会话专用代理入口与隔离进程。'}
$stop.Add_Click({Stop-OwnSession})
function Start-OwnSession {
    try{
        if(-not $script:chosenWorkspace){throw '请先选择工作文件夹。'}
        if(-not $script:chosenHandoff -and -not(Test-Path (Join-Path $data 'enrolled-handoff.json'))){throw '首次使用请导入第一步生成的交接文件。'}
        foreach($value in @($runtime,$data,$script:chosenWorkspace,$script:chosenHandoff)){if($value -match '["\r\n]'){throw '路径包含不支持的字符。'}}
        $null=New-Item -ItemType Directory -Path (Join-Path $data 'signals') -Force
        $script:stopSignal=Join-Path $data ('signals\'+[guid]::NewGuid().ToString('N')+'.stop')
        $arguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $runtime 'Run-Session.ps1')+'" -DataRoot "'+$data+'" -Workspace "'+$script:chosenWorkspace.TrimEnd('\')+'" -StopFile "'+$script:stopSignal+'" -ParentProcessId '+$PID
        if($script:chosenHandoff){$arguments+=' -HandoffPath "'+$script:chosenHandoff+'"'}
        if($DailyLaunchSmokeTest){$arguments+=' -OfflineAcceptance -MaximumSessionSeconds 8'}
        $info=[Diagnostics.ProcessStartInfo]::new("$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe",$arguments);$info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $script:worker=[Diagnostics.Process]::Start($info)
        $start.Enabled=$false;$import.Enabled=$false;$folder.Enabled=$false;$stop.Enabled=$true;$status.Text='正在核对签名、最终出口和隔离配置……'
    }catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'HONG AI CAGE')|Out-Null}
}
$start.Add_Click({Start-OwnSession})
$tray=[Windows.Forms.NotifyIcon]::new();$tray.Icon=[Drawing.SystemIcons]::Shield;$tray.Text='HONG AI CAGE';$tray.Visible=$true
$menu=[Windows.Forms.ContextMenuStrip]::new()
$settingsItem=$menu.Items.Add('设置与运行状态');$settingsItem.Add_Click({$form.Show();$form.WindowState='Normal';$form.Activate()})
$stopItem=$menu.Items.Add('停止隔离会话');$stopItem.Add_Click({Stop-OwnSession})
$exitItem=$menu.Items.Add('停止并退出');$exitItem.Add_Click({$script:userExit=$true;Stop-OwnSession;$form.Close()})
$tray.ContextMenuStrip=$menu;$tray.Add_DoubleClick({$form.Show();$form.WindowState='Normal';$form.Activate()})
$timer=[Windows.Forms.Timer]::new();$timer.Interval=1000
$timer.Add_Tick({
    if($script:worker){
        $path=Join-Path $data 'session-status.json'
        if(Test-Path $path){try{$state=Get-Content $path -Raw -Encoding UTF8|ConvertFrom-Json;switch($state.phase){'RUNNING'{$status.Text='隔离会话运行中；已核对出口：'+$state.exitIp;if($DailyLaunchSmokeTest -and -not $form.Visible -and $state.runtimeCacheReused){$script:dailyObserved=$true}}'BLOCKED'{$status.Text='会话已停止：'+$state.error}'STOPPED'{$status.Text='本次隔离会话已关闭。'}}}catch{}}
        if($script:worker.HasExited){
            if($script:worker.ExitCode -ne 0){$form.Show();$form.WindowState='Normal';$form.Activate();if(-not $status.Text.StartsWith('会话已停止：')){$status.Text='启动未完成，请查看本机 session-status.json；已保存的配置不需要重新选择。'}}
            $start.Enabled=$true;$import.Enabled=$true;$folder.Enabled=$true;$stop.Enabled=$false;$script:worker.Dispose();$script:worker=$null;$script:chosenHandoff=$null
            if($DailyLaunchSmokeTest){[IO.File]::WriteAllText((Join-Path $data 'daily-launch-test.json'),(@{automaticLaunch=$script:dailyObserved;settingsVisible=$form.Visible;loginAttempted=$false}|ConvertTo-Json),[Text.UTF8Encoding]::new($false));$script:userExit=$true;$form.Close()}
        }
    }
})
$timer.Start();$form.Add_FormClosing({param($sender,$eventArgs)
    if(-not $script:userExit -and $script:worker -and -not $UISmokeTest -and $eventArgs.CloseReason -eq 'UserClosing'){$eventArgs.Cancel=$true;$form.Hide();return}
    Stop-OwnSession;$timer.Stop();$tray.Visible=$false;$tray.Dispose()
})
if(-not $Settings -and -not $UISmokeTest -and $script:chosenWorkspace -and (Test-Path -LiteralPath (Join-Path $data 'enrolled-handoff.json'))){
    $form.Add_Shown({$form.Hide();Start-OwnSession})
}
if($UISmokeTest){$smoke=[Windows.Forms.Timer]::new();$smoke.Interval=1500;$smoke.Add_Tick({$smoke.Stop();$form.Close()});$smoke.Start()}
[Windows.Forms.Application]::Run($form)
