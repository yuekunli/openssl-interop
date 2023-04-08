:: ------------------------------------------------------
:: TroubleChute [tcno.co]'s OpenSSL build script
:: For x64, from: https://youtu.be/PMHEoBkxYaQ
:: Builds:
::   - x64 Shared <Debug/Release>
::   - x64 Static <Debug/Release>
:: ------------------------------------------------------
:: Remember to replace (((FOLDER))) with a real directory
:: ------------------------------------------------------

nmake clean
perl Configure VC-WIN64A --debug --prefix=(((FOLDER)))\DLL\x64\Debug --openssldir=H:\out\SSL
nmake test
nmake install_sw

nmake clean
perl Configure VC-WIN64A --prefix=(((FOLDER)))\DLL\x64\Release --openssldir=H:\out\SSL
nmake test
nmake install_sw

nmake clean
perl Configure VC-WIN64A --debug --prefix=(((FOLDER)))\Lib\x64\Debug --openssldir=H:\out\SSL no-shared
nmake test
nmake install_sw

nmake clean
perl Configure VC-WIN64A --prefix=(((FOLDER)))\Lib\x64\Release --openssldir=H:\out\SSL no-shared
nmake test
nmake install_sw