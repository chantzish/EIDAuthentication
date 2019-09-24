How to debug

http://blogs.msdn.com/alejacma/archive/2007/11/13/how-to-debug-lsass-exe-process.aspx

Run Virtual PC -> not working : use vmware
http://www.microsoft.com/downloads/details.aspx?FamilyId=28C97D22-6EB8-4A09-A7F7-F6C7A1F000B5

Enable kernel debugging on the virtual machine
Vista :
bcdedit /debug yes
bcdedit /dbgsettings serial debugport:2 baudrate:115200
(vmware add a serial port as COM2 - don't forget to setup Yield on CPU poll")
Xp :
......

Run kernel debugger
1) don't forget to set symbol path (path to .dll & .pdb) and source path,
else you will find only asm, not cpp code.
2) Run "ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF" to see Debugging with debug release (OutputDebug)
(needed only for Vista & later)

Set a breakpoint in a function called by lsass
================================================
!process 0 0 lsass.exe
.process /r /p 12345678    (obtained in !process with lsass.exe)
(see http://blogs.msdn.com/b/iliast/archive/2008/02/01/debugging-user-mode-processes-using-a-kernel-mode-debugger.aspx 
to see why .process /i is not recommended)
.reload  /user           (to enable pdb loading)
bp eidauthenticationpackage!lsaaplogonuserex2   (to set a breakpoint to lsaaplogonuserex2)

to enable tracing in kernel debugger, issue the following command in windbg : 
ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF


Alternative for usermode debugging of lsass.exe (necessary to run CryptoAPI Tracer script)
===============================================
cf http://blogs.msdn.com/b/spatdsg/archive/2005/12/27/507265.aspx
On the target machine:

Find the PID for LSA via  tlist.exe
Then run this command:
C:\Program Files\Debugging Tools for Windows>dbgsrv.exe -t tcp:port=1234,password=spat


On your debugger:
Run this command to attach to LSA on the remote machine.           
            I:\debugger>windbg.exe -premote tcp:server=192.168.1.102,port=1234,password=spat -p 596  -- where 596 = PID of LSASS
