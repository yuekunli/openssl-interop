:: ------------------------------------------------------
:: TroubleChute [tcno.co]'s OpenSSL build script
:: For x32, from: https://youtu.be/PMHEoBkxYaQ
:: Builds:
::   - x32 Shared <Debug/Release>
::   - x32 Static <Debug/Release>
:: ------------------------------------------------------
:: Remember to replace (((FOLDER))) with a real directory
:: ------------------------------------------------------

nmake clean
perl Configure VC-WIN32 --debug --prefix=(((FOLDER)))\DLL\x32\Debug --openssldir=H:\out\SSL
nmake test
nmake install_sw

nmake clean
perl Configure VC-WIN32 --prefix=(((FOLDER)))\DLL\x32\Release --openssldir=H:\out\SSL
nmake test
nmake install_sw

nmake clean
perl Configure VC-WIN32 --debug --prefix=(((FOLDER)))\Lib\x32\Debug --openssldir=H:\out\SSL no-shared
nmake test
nmake install_sw

nmake clean
perl Configure VC-WIN32 --prefix=(((FOLDER)))\Lib\x32\Release --openssldir=H:\out\SSL no-shared
nmake test
nmake install_sw