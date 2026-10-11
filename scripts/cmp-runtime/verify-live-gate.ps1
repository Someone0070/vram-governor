param(
  [ValidateSet('D1','D2','D3','D4','D6')]
  [string]$Gate
)

$ErrorActionPreference = 'Stop'
$lbKey = 'C:\Users\Sasha\.ssh\lb_proxy_deploy'
$cmpKey = 'C:\Users\Sasha\.ssh\cmp170_proxmox'

function Invoke-SSH([string]$Key, [string]$HostName, [string]$Command) {
  & ssh -i $Key -o BatchMode=yes -o StrictHostKeyChecking=yes $HostName $Command
  if ($LASTEXITCODE -ne 0) { throw "SSH verification failed on $HostName" }
}

switch ($Gate) {
  'D1' {
    Invoke-SSH $lbKey 'root@10.0.0.115' 'python3 /root/verify-live-managed-comfy.py'
    Invoke-SSH $cmpKey 'root@10.0.0.60' 'bash /root/verify-live-harness-durability.sh'
    Invoke-SSH $lbKey 'root@10.0.0.115' 'python3 /root/verify-live-cmp-final.py'
  }
  'D2' { Invoke-SSH $lbKey 'root@10.0.0.115' 'python3 /root/verify-live-cmp-final.py' }
  'D3' { Invoke-SSH $lbKey 'root@10.0.0.115' 'python3 /root/verify-live-cmp-final.py' }
  'D4' { Invoke-SSH $lbKey 'root@10.0.0.115' 'python3 /root/verify-live-cmp-controls.py' }
  'D6' {
    Invoke-SSH $lbKey 'root@10.0.0.115' 'python3 /root/verify-live-cmp-final.py'
    Invoke-SSH $cmpKey 'root@10.0.0.60' "systemctl is-active --quiet comfyui.service video-worker.service llama-server.service comfy-harness.service vram-governor-runtime-tunnel.service vram-governor-node-agent.service"
    Invoke-SSH $lbKey 'root@10.0.0.115' "systemctl is-active --quiet vram-governor-controller.service nginx.service postgresql.service"
  }
}
Write-Output "${Gate}_OK"
