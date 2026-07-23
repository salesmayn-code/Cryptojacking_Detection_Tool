# XMRig Safe Local Lab (No VM)

This folder contains safe simulation tools for detector testing.

## Build EXEs
```powershell
cd C:\FYP\fyp\tools\xmrig-safe-lab
powershell -ExecutionPolicy Bypass -File .\build_fake_pool_exe.ps1
powershell -ExecutionPolicy Bypass -File .\build_simulator_exe.ps1
```

## Run flow
Terminal 1:
```powershell
cd C:\FYP\fyp\tools\xmrig-safe-lab\dist
.\fake-pool.exe --port 3333
```

Terminal 2:
```powershell
cd C:\FYP\fyp\tools\xmrig-safe-lab\dist
.\xmrig.exe --host 127.0.0.1 --port 3333 --workers 6 --cpu-intensity 95 --rpc-interval 1
```

This intentionally matches policy names (`xmrig`) and keeps CPU + miner-port traffic in the same worker processes.
