@echo off
setlocal
cd /d "%~dp0"
if not exist out mkdir out
javac -d out backend\src\com\loginapp\*.java
if errorlevel 1 exit /b 1
java -cp out com.loginapp.LoginServer
