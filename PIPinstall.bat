@echo off
chcp 65001
setlocal enabledelayedexpansion

cls
title Python包安装工具

:: 使用 %~dp0 获取批处理脚本所在的目录，然后构建Python路径
set "SCRIPT_DIR=%~dp0"
set "AUTO_PYTHON_ROOT=!SCRIPT_DIR!python313"
set "TARGET_DIR=!SCRIPT_DIR!python313"

echo ================================
echo        Python包安装工具
echo ================================
echo.
echo 自动检测到的Python路径: !AUTO_PYTHON_ROOT!
echo.

:SETUP_PATH
:: 询问用户是否使用自动检测的路径
set /p "USE_AUTO=是否使用自动检测的Python路径? (Y/n): "
if /i "!USE_AUTO!"=="n" (
    set /p "PYTHON_ROOT=请输入Python的安装根路径: "
) else (
    set "PYTHON_ROOT=!AUTO_PYTHON_ROOT!"
)

:: 检查pip.exe是否存在
set "PIP_EXE=!PYTHON_ROOT!\Scripts\pip3.exe"
if not exist "!PIP_EXE!" (
    echo.
    echo 【错误】在 !PYTHON_ROOT!\Scripts\ 目录下未找到 pip.exe，请检查Python路径是否正确。
    echo.
    goto :SETUP_PATH
)

:MENU
echo.
echo ================================
echo 当前Python路径: !PYTHON_ROOT!
echo 安装目标目录: !TARGET_DIR!
echo ================================
echo.
set /p "PKG_NAME=请输入要安装的Python包名称（输入 'quit' 并按回车退出）: "

:: 检查是否退出
if /i "!PKG_NAME!"=="quit" goto :EXIT

:: 执行安装命令
echo.
echo 【信息】正在执行安装命令...
echo 【命令】 "!PIP_EXE!" install "!PKG_NAME!" --target "!TARGET_DIR!"
echo.
"!PIP_EXE!" install "!PKG_NAME!" --target "!TARGET_DIR!"

:: 检查安装结果
if !errorlevel! equ 0 (
    echo.
    echo 【信息】包 '!PKG_NAME!' 安装成功！
) else (
    echo.
    echo 【错误】包 '!PKG_NAME!' 安装可能失败，请检查包名称是否正确或查看上述错误信息。
)

echo.
pause
cls
goto :MENU

:EXIT
echo.
echo 退出安装工具。
pause
endlocal