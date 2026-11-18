@echo off
rem Start-menu / desktop shortcut target. Runs the bundled Node on the bundled StarClaw:
rem `starclaw app` opens the console in the default browser. Closing this window stops StarClaw.
setlocal
title StarClaw (close this window to stop it)
"%~dp0node\node.exe" "%~dp0app\node_modules\starclaw\dist\cli.js" app %*
if errorlevel 1 (
  echo.
  echo StarClaw stopped with the error above.
  pause
)
